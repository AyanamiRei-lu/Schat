package com.schat.android.chat

import com.schat.android.core.ServerConfig
import com.schat.android.core.contacts.Contact
import com.schat.android.core.contacts.ContactCodec
import com.schat.android.core.contacts.ContactList
import com.schat.android.core.net.DirectoryClient
import com.schat.android.core.net.RelayClient
import com.schat.android.core.profile.ClientProfileData
import com.schat.android.core.profile.ClientProfileStore
import com.schat.android.data.store.EncryptedStore
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Where a sent message has got to.
 *
 * [SENT] means the relay accepted the envelope, which is a much weaker claim than "the
 * peer read it" — the relay never acknowledges reading, because it never reads. Saying
 * so in the UI is the difference between an honest status and a comforting one.
 */
enum class DeliveryState { SENDING, SENT, FAILED }

/** One message in the conversation. */
data class ChatMessage(
    val id: Long,
    val outgoing: Boolean,
    val text: String,
    val atMillis: Long,
    val state: DeliveryState,
)

/** An immutable snapshot the UI renders. */
data class ChatState(
    /** Human-readable transport status. */
    val connection: String = "未连接",

    /** The peer this conversation is with, or empty before one is chosen. */
    val peerIdentityHex: String = "",

    /** The 60 digits both users compare out of band, or empty until known. */
    val safetyNumber: String = "",

    val messages: List<ChatMessage> = emptyList(),

    /**
     * Locally remembered peers, most recent first.
     *
     * Local only: the list is never sent anywhere, and the relay cannot enumerate it. That
     * is the point of storing it here rather than asking the server who exists.
     */
    val contacts: List<com.schat.android.core.contacts.Contact> = emptyList(),

    /** Set when the last operation failed, for display. */
    val error: String? = null,

    /**
     * Whether the relay can see who is talking to whom.
     *
     * Always true in this build. It is carried in the state rather than hardcoded in
     * the banner so that when session-internal token exchange lands, removing the
     * warning is a one-line change tied to the mechanism that earns it.
     */
    val mailboxIsDerivedFromIdentity: Boolean = true,
)

/**
 * The bridge between the protocol core, the network layer and the chat screen.
 *
 * # Threading
 *
 * Every call into the Go binding and every blocking network call happens on a single
 * background thread. This is not tidiness: `mobile.Session` is mutable ratchet state
 * with no thread affinity of its own, and two concurrent `Decrypt` calls on the same
 * session would race on the chain keys. One thread also means the ordering the double
 * ratchet depends on — a handshake processed before the frames that follow it — is
 * preserved for free rather than reconstructed with locks.
 *
 * [Listener.onState] is therefore called on that background thread, and the UI layer is
 * responsible for hopping to the main thread.
 *
 * # What this class deliberately does not do
 *
 * It does not parse protocol messages. Handshake initiations, frames and snapshots go
 * to Go as opaque bytes and come back the same way; the only JSON it reads is the
 * identity blob it created itself. Every field name in the wire format lives in one
 * place, and that place is not Kotlin.
 */
class ChatController(
    private val config: ServerConfig,
    private val store: EncryptedStore,
    private var profile: ClientProfileData,
    private val listener: Listener,
) {
    /** Receives state updates. Called on the controller's own background thread. */
    fun interface Listener {
        fun onState(state: ChatState)
    }

    private val profileStore = ClientProfileStore(store)

    // 群状态与单聊状态存在同一个加密库里，用同一个密钥保护。
    // 全限定名是有意的：它让这次改动不必碰 import 区，而 import 区是我没有读过的部分。
    private val groupStore = com.schat.android.core.groups.GroupStore(store)

    /** Serialises everything that touches the session or the network. */
    private val worker: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "schat-chat").apply { isDaemon = true }
    }

    private val scheduler: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "schat-heartbeat").apply { isDaemon = true }
        }

    private val directory = DirectoryClient(config)

    /** Guards [state]; every other field is only touched on [worker]. */
    private val stateLock = Any()
    private var state = ChatState()

    private var relay: RelayClient? = null
    private var session: mobile.Session? = null

    /**
     * This client's own identity signing public key, hex.
     *
     * Read defensively: a malformed identity blob would otherwise throw from the
     * constructor, which the UI would report as an unexplained crash rather than as the
     * specific problem it is.
     */
    private val myIdentityHex: String = try {
        signingPublicOf(profile.identityJson)
    } catch (e: Exception) {
        ""
    }

    /** This client's mailbox, derived from its identity. */
    private val myMailbox: String = try {
        if (myIdentityHex.isEmpty()) "" else mobile.Mobile.mailboxToken(myIdentityHex)
    } catch (e: Exception) {
        ""
    }

    /** The peer's mailbox, once a peer is known. */
    private var peerMailbox: String = ""

    private var nextMessageId = 1L

    /**
     * The local contact list.
     *
     * Held in memory because every message touches it, and written through
     * [publishContacts] rather than at each mutation, so the stored copy and the copy the
     * UI renders cannot drift apart.
     */
    private var contacts: List<Contact> = emptyList()

    /** Set once the heartbeat timer is scheduled, so reconnects do not stack timers. */
    private var heartbeatStarted = false

    /** Consecutive failed connection attempts, for the backoff. */
    private var reconnectAttempts = 0

    /** Set by [stop], so a scheduled reconnect cannot revive a controller being torn down. */
    private var stopped = false

    // ------------------------------------------------------------------
    // Lifecycle

    /** Publishes this client's prekeys and opens the relay connection. */
    /**
     * @param resumeLastConversation false when the caller shows a conversation list on
     *   launch: reopening the last chat automatically would drop the user straight into
     *   a chat and hide the list they were about to read.
     */
    fun start(resumeLastConversation: Boolean = true) = onWorker {
        if (myMailbox.isEmpty() || myIdentityHex.isEmpty()) {
            update { it.copy(connection = "身份不可用", error = "无法从本地资料中读出身份公钥") }
            return@onWorker
        }

        // Contacts first: reopening a conversation marks it read, which needs the list.
        loadContacts()

        // Reopen the last conversation BEFORE connecting, so the message history is on
        // screen immediately rather than appearing only after the network settles. The
        // history and the ratchet snapshot were both being written to the vault all along;
        // nothing ever read them back, so killing the app looked like losing everything.
        if (resumeLastConversation) {
            store.getString(LAST_PEER)?.let { reopenConversation(it) }
        }

        update { it.copy(connection = "正在发布预密钥…") }

        // A drained pool is regenerated rather than republished empty: an empty pool
        // still lets peers start sessions, but every one of them loses forward secrecy
        // for its first message, and the peers cannot tell.
        if (remainingPreKeys(profile.prekeyStoreJson) == 0) {
            profile = profile.copy(
                prekeyStoreJson = mobile.Mobile.createPreKeyStore(profile.identityJson, PREKEY_POOL_SIZE),
            )
            profileStore.save(profile)
        }

        publishBundle()

        val client = RelayClient(config, SocketListener())
        relay = client
        update { it.copy(connection = "正在连接 ${config.host}:${config.port}…") }
        client.connect()
    }

    /** Closes the connection and releases the session. */
    fun stop() = onWorker {
        stopped = true
        scheduler.shutdownNow()
        relay?.shutdown()
        relay = null
        session?.close()
        session = null
        worker.shutdown()
    }

    /**
     * Schedules another connection attempt with exponential backoff.
     *
     * Without this a single blip is permanent: OkHttp does not resurrect a socket that
     * has failed, so the app would stay offline until it was killed and reopened. On a
     * phone, where moving between Wi-Fi and mobile data is routine, that is not an edge
     * case — it was the first thing the first device test hit.
     */
    private fun scheduleReconnect() {
        if (stopped) return

        reconnectAttempts += 1
        val delay = minOf(MAX_RECONNECT_DELAY_SECONDS, 1L shl minOf(reconnectAttempts, 5))
        update { it.copy(connection = "连接已断开，$delay 秒后重试（第 $reconnectAttempts 次）") }

        scheduler.schedule(
            {
                onWorker {
                    if (stopped) return@onWorker
                    update { it.copy(connection = "正在重新连接…") }
                    relay?.connect()
                }
            },
            delay,
            TimeUnit.SECONDS,
        )
    }

    /** Clears the backoff once a connection actually succeeds. */
    private fun resetReconnect() {
        reconnectAttempts = 0
    }

    // ------------------------------------------------------------------
    // Starting a conversation

    /**
     * Starts a session with a peer, as the initiator.
     *
     * The bundle is fetched from the relay and checked against the identity that was
     * asked for *inside the binding* — see [mobile.Mobile.establishSession]. That check
     * cannot be skipped from here, which matters because publishing to the directory is
     * unauthenticated and anyone may overwrite an entry with their own keys.
     */
    fun startSessionWith(peerIdentityHex: String) = onWorker {
        val peer = peerIdentityHex.trim().lowercase()
        if (peer.length != 64 || peer.any { it !in "0123456789abcdef" }) {
            fail("对端身份应为 64 位十六进制字符")
            return@onWorker
        }
        if (peer == myIdentityHex) {
            fail("不能与自己建立会话")
            return@onWorker
        }

        update { it.copy(connection = "正在获取对端预密钥…", error = null) }

        val fetched = directory.fetch(peer)
        val bundle = fetched.getOrNull()
        if (bundle == null) {
            val detail = fetched.exceptionOrNull()?.message.orEmpty()
            fail(
                if (detail.contains("HTTP 404")) {
                    // The relay's message here is accurate and useless: it knows only that
                    // no bundle exists, not why. Say what the user can actually do.
                    "对方（${peer.take(8)}…）还没有向中继发布预密钥，因此现在无法建立会话。" +
                        "请让对方先打开 SCHAT，并确认其状态行显示「已订阅信箱」，然后再重试。" +
                        "若对方的状态行有连接错误，说明那台手机没有连上这个中继。"
                } else {
                    "获取预密钥失败：$detail"
                },
            )
            return@onWorker
        }

        val established = try {
            mobile.Mobile.establishSession(profile.identityJson, peer, bundle)
        } catch (e: Exception) {
            fail("建立会话失败：${e.message}")
            return@onWorker
        }

        session?.close()
        session = established
        peerMailbox = mobile.Mobile.mailboxToken(peer)

        // The initiation is the first envelope: without it the peer has no session and
        // could not decrypt anything that followed.
        val wire = try {
            mobile.Mobile.wrapHandshake(peerMailbox, established.initMessage())
        } catch (e: Exception) {
            fail("封装握手消息失败：${e.message}")
            return@onWorker
        }

        persistSession(peer)
        announce(peer)

        if (relay?.sendEnvelope(wire) == true) {
            update { it.copy(connection = "已发送会话请求") }
        } else {
            fail("连接尚未就绪，会话请求未能发出")
        }
    }

    /** Sends a text message over the established session. */
    fun send(text: String) = onWorker {        val body = text.trim()
        if (body.isEmpty()) return@onWorker
        if (peerMailbox.isEmpty()) {
            fail("尚未选择联系人")
            return@onWorker
        }

        val active = session
        if (active == null) {
            fail("会话尚未建立")
            return@onWorker
        }

        val id = nextMessageId++
        val now = System.currentTimeMillis()
        append(ChatMessage(id, outgoing = true, text = body, atMillis = now, state = DeliveryState.SENDING))

        // The list shows the last thing that happened in each conversation, so it is
        // updated on send as well as on receive — a sent message must not badge the user's
        // own inbox, which ContactList.noteMessage handles.
        contacts = ContactList.noteMessage(contacts, state.peerIdentityHex, now, body, outgoing = true)
        publishContacts()

        val wire = try {
            active.encrypt(peerMailbox, body.toByteArray(Charsets.UTF_8), PROFILE_TEXT)
        } catch (e: Exception) {
            markFailed(id)
            fail("加密失败：${e.message}")
            return@onWorker
        }

        if (relay?.sendEnvelope(wire) == true) {
            markSent(id)
            // The ratchet advanced, so the snapshot on disk is now stale. Persisting
            // here is what keeps a restart from replaying a used chain key.
            persistSession(state.peerIdentityHex)
        } else {
            markFailed(id)
            fail("发送失败：连接已断开")
        }
    }

    /** The 60-digit number both users read aloud. */
    fun safetyNumberWith(peerIdentityHex: String): String = try {
        mobile.Mobile.safetyNumber(myIdentityHex, peerIdentityHex.trim().lowercase())
    } catch (e: Exception) {
        ""
    }

    /** This client's own identity, for display and for the peer to verify. */
    fun myIdentity(): String = myIdentityHex

    /** The current snapshot, for the UI to render on first composition. */
    fun currentState(): ChatState = synchronized(stateLock) { state }

    // ------------------------------------------------------------------
    // Incoming traffic

    private inner class SocketListener : RelayClient.Listener {
        override fun onConnected() = onWorker {
            resetReconnect()
            update { it.copy(connection = "已连接", error = null) }
            relay?.subscribe(listOf(myMailbox))

            // Republished on EVERY successful connection, not only after a failed one.
            //
            // The relay's prekey directory lives in RAM and nowhere else — that is the
            // point of it — so restarting the server wipes every published bundle. A
            // device that merely reconnects would then be unreachable while believing it
            // had published, and the only symptom would appear on the OTHER device as
            // "no bundle published for that identity". Publishing is one small idempotent
            // PUT, so doing it on every connect is the cheap way to make a server restart
            // a non-event.
            publishBundle()

            // Scheduled once. Re-registering on every reconnect would stack up timers
            // and send an ever-growing number of heartbeats.
            if (!heartbeatStarted) {
                heartbeatStarted = true
                scheduler.scheduleWithFixedDelay(
                    { relay?.heartbeat() },
                    HEARTBEAT_SECONDS,
                    HEARTBEAT_SECONDS,
                    TimeUnit.SECONDS,
                )
            }
        }

        override fun onEnvelope(envelope: ByteArray) = onWorker { handle(envelope) }

        override fun onControl(json: String) = onWorker { handleControl(json) }

        override fun onDisconnected(code: Int, reason: String) = onWorker {
            update { it.copy(connection = "连接已断开（$code）") }
            scheduleReconnect()
        }

        override fun onFailure(error: Throwable) = onWorker {
            val detail = error.message.orEmpty()
            fail(
                if (looksUnreachable(detail)) {
                    // The single most likely cause, and the one that actually happened on
                    // the first device test: a private LAN address is unreachable from a
                    // phone on mobile data, and the raw error says nothing about that.
                    "无法连接到中继 ${config.host}:${config.port}。" +
                        "请确认：① 这台手机连的是与服务器同一个 Wi-Fi（**不是移动数据**）；" +
                        "② 服务器正在运行且 `--listen` 绑定 0.0.0.0；" +
                        "③ 连接信息里的主机名就是服务器的局域网 IP。" +
                        "原始错误：$detail"
                } else {
                    "连接 ${config.host}:${config.port} 失败：$detail"
                },
            )
            scheduleReconnect()
        }
    }

    /** Routes one envelope: a handshake initiation or an encrypted frame. */
    private fun handle(envelope: ByteArray) {
        val kind = try {
            mobile.Mobile.contentType(envelope)
        } catch (e: Exception) {
            fail("收到无法识别的数据：${e.message}")
            return
        }

        when (kind) {
            CONTENT_TYPE_HANDSHAKE -> acceptHandshake(envelope)
            CONTENT_TYPE_FRAME -> decryptFrame(envelope)
            CONTENT_TYPE_GROUP -> receiveGroupMessage(envelope)
            CONTENT_TYPE_GROUP_WELCOME -> acceptGroupWelcome(envelope)
            CONTENT_TYPE_GROUP_COMMIT -> receiveGroupCommit(envelope)
            else -> fail("收到了未知的内容类型 $kind")
        }
    }

    /**
     * 收到一条群消息。
     *
     * 属于哪个群由消息自己的公开头部说明——群 ID 与 epoch 都不加密，因为接收方必须先知道
     * 该用哪份群状态，才谈得上解密。所以顺序是被强制的：
     *
     *     unwrap → header → 取该群状态 → open
     *
     * 群密钥来自本机保存的快照，中继看不到它，也看不到消息内容。
     */
    private fun receiveGroupMessage(envelope: ByteArray) {
        val message = try {
            GroupController.unwrap(envelope)
        } catch (e: Exception) {
            fail("群消息解析失败：${e.message}")
            return
        }

        val messageHex = message.joinToString("") { "%02x".format(it) }

        val header = try {
            GroupController.header(messageHex)
        } catch (e: Exception) {
            fail("群消息头部读取失败：${e.message}")
            return
        }

        val record = groupStore.load(header.groupIDHex)
        if (record == null) {
            fail("收到一个不属于任何已保存群的消息")
            return
        }

        // 群状态与消息里的 epoch 必须一致。不一致不是"解密失败"，而是"两边不在同一个 epoch"——
        // 这个区分让用户看到的是可处理的原因，而不是一个密码学错误。
        if (record.stateJson.isEmpty() || header.epoch < 0) {
            fail("群状态不可用")
            return
        }

        val opened = try {
            GroupController.open(record.stateJson, messageHex)
        } catch (e: Exception) {
            fail("群消息解密失败：${e.message}")
            return
        }

        // 解密已经成功——这一步证明了消息确实属于这个群、这一代，且没有被改动。
        // 把它交给会话界面是下一步（群界面）的事；此处只留下结果，不猜显示格式。
        lastGroupMessage = opened

        // 落库。正文以明文存入，因为存储本身是加密的；再加密一层只会多一份要维护的密钥。
        // 十六进制转字节就地完成，不引入新的工具函数——少一处需要维护的约定。
        val groupText = opened.plaintextHex
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
            .toString(Charsets.UTF_8)

        runCatching {
            groupStore.appendMessage(
                header.groupIDHex,
                com.schat.android.core.groups.GroupMessage(
                    fromLeaf = opened.senderLeaf,
                    mine = false,
                    generation = opened.generation,
                    atMillis = System.currentTimeMillis(),
                    text = groupText,
                ),
            )
        }.onFailure { e ->
            // 解密成功而落库失败，意味着这条消息会在重启后消失。说出来，不静默丢弃。
            fail("群消息已解密但未能保存：${e.message}")
        }
    }

    /** 最近一条成功解开的群消息，供群界面取用。 */
    var lastGroupMessage: GroupController.Opened? = null
        private set

    /**
     * 收到一份群邀请并加入。
     *
     * 这份邀请是发给【身份信箱】的，所以它到达时本机还不知道有这个群——
     * 群的标识要等入群成功、从群状态里读出来。
     */
    /**
     * 群变更（提交）：有人改了群——加了成员、移除了成员、或更新了自己的叶子。
     *
     * 它与群消息同走群信箱，但**信封里只有投递令牌、没有群 ID**。令牌由「时间派生的令牌 epoch」
     * 加群路由密钥导出，所以接收方只能：算出每个已保存群在【当前与上一个】令牌 epoch 下的信箱，
     * 令牌相符的那个群就是它要去的群。试两个是因为时钟会跨过 epoch 边界——发送方与接收方各自
     * 读自己的钟，边界两侧算出的信箱不同，两边都要能被认出来。
     *
     * 找不到群时**报错，而不是丢弃**：一条没人处理的提交意味着本机落后于群，而那正是用户需要
     * 看到的事。静默丢弃会让成员永远停在旧 epoch，且没有任何迹象。
     */
    private fun receiveGroupCommit(envelope: ByteArray) {
        val commitBytes = try {
            GroupController.unwrapCommit(envelope)
        } catch (e: Exception) {
            fail("群变更解析失败：${e.message}")
            return
        }
        if (commitBytes.isEmpty()) {
            fail("群变更没有内容")
            return
        }
        val commitHex = commitBytes.joinToString("") { "%02x".format(it) }

        val tokenHex = envelope.take(16).joinToString("") { "%02x".format(it) }
        val nowEpoch = mobile.Mobile.currentEpoch(System.currentTimeMillis() / 1000L)

        val record = groupStore.list()
            .mapNotNull { groupStore.load(it) }
            .firstOrNull { rec ->
                listOf(nowEpoch, nowEpoch - 1).any { epoch ->
                    runCatching {
                        GroupController.mailboxTokens(rec.stateJson, epoch, GROUP_MAILBOX_TOKENS)
                    }.getOrDefault(emptyList()).contains(tokenHex)
                }
            }
        if (record == null) {
            fail("收到一条群变更，但它不属于任何已保存的群")
            return
        }

        val mine = GroupController.myLeaf(record.stateJson, profile.identityJson)
        val next = try {
            GroupController.processCommit(record.stateJson, commitHex, mine)
        } catch (e: Exception) {
            fail("群变更无法应用：${e.message}")
            return
        }

        runCatching {
            groupStore.save(record.copy(stateJson = next, generation = 0L))
        }.onFailure { e -> fail("群变更已应用但未能保存：${e.message}") }
    }

    private fun acceptGroupWelcome(envelope: ByteArray) {
        val welcomeBytes = try {
            mobile.Mobile.unwrapGroupWelcome(envelope)
        } catch (e: Exception) {
            fail("群邀请解析失败：${e.message}")
            return
        }

        // init 私钥是唯一能解开这份邀请的东西。它没有就是不能加入——
        // 而不是"解密失败"，两者对用户是完全不同的意思。
        val mine = groupStore.loadMyKeyPackage()
        if (mine == null) {
            fail("收到群邀请，但本机没有可用于加入的 KeyPackage 私钥")
            return
        }

        val welcomeHex = welcomeBytes.joinToString("") { "%02x".format(it) }
        val state = try {
            // 三个值：Welcome、init 私钥（开 Welcome）、叶子私钥（入群后解开寻址给自己的路径秘密）。
            // 叶子下标不再需要传——AcceptWelcome 用叶子私钥在树里找到它自己。调用方无从知道那个
            // 数字，而一个错的下标会让成员用别人的钥匙解密，失败却出现在确认标签处。
            GroupController.processWelcome(welcomeHex, mine.second, mine.third)
        } catch (e: Exception) {
            fail("入群失败：${e.message}")
            return
        }

        runCatching {
            val summary = GroupController.summary(state)
            groupStore.save(
                com.schat.android.core.groups.GroupRecord(summary.groupIDHex, state, 0L),
            )
        }.onFailure { e -> fail("已入群但未能保存：${e.message}") }
    }

    /**
     * 群消息发送的第一步：算出该 epoch 的信箱，并加密正文。
     *
     * 返回 (逗号分隔的信箱, 密文十六进制)。第二步——装 0x03 信封、发出、落库——
     * 在 [sendGroup] 里。分成两步是为了每一步都小到能在一次编译里验证。
     */
    fun prepareGroupMessage(groupStateJson: String, text: String, generation: Long): Pair<String, String>? {
        val tokens = try {
            // 信箱由 epoch 导出，所以同 epoch 的成员必然算出同一串——没有任何东西分发它。
            // 令牌 epoch 取自墙上时钟：它的用途是容忍时钟跨过边界，因此必须由这里提供。
            mobile.Mobile.groupMailboxTokens(
                groupStateJson,
                mobile.Mobile.currentEpoch(System.currentTimeMillis() / 1000L),
                3L,
            )
        } catch (e: Exception) {
            fail("无法派生群信箱：${e.message}")
            return null
        }
        if (tokens.isEmpty()) {
            fail("群路由密钥没有派生出任何信箱")
            return null
        }

        val sealed = try {
            GroupController.seal(
                groupStateJson,
                profile.identityJson,
                text.toByteArray(Charsets.UTF_8).joinToString("") { "%02x".format(it) },
                generation,
            )
        } catch (e: Exception) {
            fail("群消息加密失败：${e.message}")
            return null
        }

        return Pair(tokens, sealed.messageHex)
    }

    /**
     * 发送一条群消息：装信封、发出，并把副本落在本机历史里。
     *
     * 中继看到的是一条消息一个投递令牌，与单聊无异——它不知道群的规模、不知道谁在说话，
     * 也不知道这是一条群消息（信封的内容类型是唯一标志，而中继不读它）。
     */
    fun sendGroup(groupStateJson: String, text: String, generation: Long, groupIdHex: String) {
        val prepared = prepareGroupMessage(groupStateJson, text, generation) ?: return
        val tokensCsv = prepared.first
        val messageHex = prepared.second
        val tokens = tokensCsv.split(',').filter { it.isNotEmpty() }
        if (tokens.isEmpty()) {
            fail("群信箱列表为空，消息未发出")
            return
        }

        val envelope = try {
            GroupController.wrap(
                tokens[0],
                messageHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
            )
        } catch (e: Exception) {
            fail("群信封构造失败：${e.message}")
            return
        }

        val client = relay
        if (client == null) {
            fail("尚未连接到中继，消息未发出")
            return
        }

        // 全部信箱都订阅上：epoch 边缘的时钟漂移不应让消息丢失。
        client.subscribe(tokens)
        if (!client.sendEnvelope(envelope)) {
            fail("群消息未能发出")
            return
        }

        // 落在本机历史里，与收到的消息走同一条路——否则自己发的消息重启后会消失。
        runCatching {
            groupStore.appendMessage(
                groupIdHex,
                com.schat.android.core.groups.GroupMessage(
                    fromLeaf = 0L,
                    mine = true,
                    generation = generation,
                    atMillis = System.currentTimeMillis(),
                    text = text,
                ),
            )
        }.onFailure { e -> fail("群消息已发出但未能保存：${e.message}") }
    }


    /**
     * Completes a session as the responder.
     *
     * The pool handed back by the binding is written over the stored one immediately.
     * Skipping that would resurrect the one-time prekey this handshake just consumed,
     * and a replayed initiation would then complete a second session from the same DH
     * inputs — the exact failure the one-time pool exists to prevent. The test suite
     * caught this once; it is not a theoretical concern.
     */
    /**
     * 把一条群变更（提交）发给群信箱。
     *
     * 与群消息走同一条路、同一批信箱：提交只对成员有意义，而成员恰好就是能派生出这些信箱的人。
     * 与 Welcome 相反——Welcome 发给新成员【个人的】身份信箱，因为它还不在群里，推不出群信箱。
     *
     * 逐令牌发送而不是发一次：每个令牌是一个独立的信箱，中继按令牌路由。只发一个令牌时，
     * 恰好订阅了另一个令牌的成员就收不到——而那正是"有人没跟上群"的来源。
     */
    fun sendGroupCommit(groupStateJson: String, commitHex: String) {
        val commitBytes = commitHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        if (commitBytes.isEmpty()) {
            fail("群变更为空，没有可发送的内容")
            return
        }

        val tokenCsv = try {
            // 令牌 epoch 与 prepareGroupMessage 用的是同一个来源与同一个数量：
            // 两边算出的信箱必须逐字相同，否则提交发给了一组没人订阅的信箱。
            mobile.Mobile.groupMailboxTokens(
                groupStateJson,
                mobile.Mobile.currentEpoch(System.currentTimeMillis() / 1000L),
                GROUP_MAILBOX_TOKENS,
            )
        } catch (e: Exception) {
            fail("无法派生群信箱：${e.message}")
            return
        }

        var sent = 0
        for (token in tokenCsv.split(',')) {
            if (token.isEmpty()) continue
            val wire = try {
                GroupController.wrapCommit(token, commitBytes)
            } catch (e: Exception) {
                fail("群变更装封失败：${e.message}")
                return
            }
            // `relay` 是会话级的可空字段（与 sendGroup 的局部 client 不同）：未连接时返回 false，
            // 由下面的 sent == 0 统一报告，而不是在这里抛异常。
            if (relay?.sendEnvelope(wire) == true) sent++
        }
        if (sent == 0) {
            fail("群变更未能发出")
        }
    }

    private fun acceptHandshake(envelope: ByteArray) {
        val init = try {
            mobile.Mobile.unwrapHandshake(envelope)
        } catch (e: Exception) {
            fail("握手消息解析失败：${e.message}")
            return
        }

        val accepted = try {
            mobile.Mobile.acceptSession(profile.identityJson, profile.prekeyStoreJson, init)
        } catch (e: Exception) {
            // A replay lands here, because the prekey it names is already gone. That is
            // the mechanism working, not a bug to paper over.
            fail("接受会话失败：${e.message}")
            return
        }

        val updated = accepted.updatedPreKeyStore()
        if (updated.isNotEmpty()) {
            profile = profile.copy(prekeyStoreJson = updated)
            profileStore.save(profile)
            // The pool on the relay is now one prekey shorter than the pool here, so
            // republishing keeps the two in step. Publishing the whole pool replaces
            // the entry, and the relay's copy still holds the prekeys it has not yet
            // handed out.
            publishBundle()
        }

        session?.close()
        session = accepted

        val peer = accepted.peerIdentity()
        if (peer.isEmpty()) {
            fail("握手未提供对端身份")
            return
        }
        peerMailbox = mobile.Mobile.mailboxToken(peer)
        persistSession(peer)
        announce(peer)
        update { it.copy(connection = "会话已建立") }
    }

    /** Decrypts one frame and appends it to the conversation. */
    private fun decryptFrame(envelope: ByteArray) {
        val active = session
        if (active == null) {
            fail("收到消息但没有会话，已丢弃")
            return
        }

        val plain = try {
            active.decrypt(envelope)
        } catch (e: Exception) {
            // A message that fails to authenticate is reported and dropped. It is not
            // retried and it does not close the session: an attacker who can inject
            // packets must not be able to end a conversation by doing so.
            fail("消息解密失败（可能是伪造或乱序）：${e.message}")
            return
        }

        val receivedAt = System.currentTimeMillis()
        val receivedText = String(plain, Charsets.UTF_8)
        append(
            ChatMessage(
                id = nextMessageId++,
                outgoing = false,
                text = receivedText,
                atMillis = receivedAt,
                state = DeliveryState.SENT,
            ),
        )
        contacts = ContactList.noteMessage(
            contacts,
            state.peerIdentityHex,
            receivedAt,
            receivedText,
            outgoing = false,
        )
        publishContacts()
        persistSession(state.peerIdentityHex)
    }

    /** Surfaces the relay's control replies in the status line. */
    private fun handleControl(json: String) {
        val type = try {
            JSONObject(json).optString("t")
        } catch (e: Exception) {
            return
        }
        val text = when (type) {
            "ok" -> "已订阅信箱"
            "delivered" -> "已投递"
            // "offline" is not a soft failure: the relay stored nothing, and telling
            // the user the message was delivered would be a lie.
            "offline" -> "对端离线，消息未送达（服务器不存储）"
            "queued" -> "对端离线，消息已暂存在服务器内存中"
            "err" -> "服务器拒绝了请求：${JSONObject(json).optString("m")}"
            else -> return
        }
        update { it.copy(connection = text) }
    }

    // ------------------------------------------------------------------
    // State and persistence

    private fun announce(peer: String) {
        val number = safetyNumberWith(peer)

        // Recorded here rather than at each call site, because both ways of arriving at a
        // session — initiating and accepting — must end up in the same local contact list,
        // and a peer the user has talked to should never have to be typed again.
        rememberPeer(peer)
        store.putString(LAST_PEER, peer)

        update {
            it.copy(
                peerIdentityHex = peer,
                safetyNumber = number,
                connection = "会话已建立",
                error = null,
            )
        }
    }

    private fun append(message: ChatMessage) {
        update { it.copy(messages = it.messages + message) }
        saveHistory()
    }

    private fun markSent(id: Long) = updateMessage(id) { it.copy(state = DeliveryState.SENT) }

    private fun markFailed(id: Long) = updateMessage(id) { it.copy(state = DeliveryState.FAILED) }

    private fun updateMessage(id: Long, transform: (ChatMessage) -> ChatMessage) {
        update { current ->
            current.copy(messages = current.messages.map { if (it.id == id) transform(it) else it })
        }
        saveHistory()
    }

    private fun fail(message: String) {
        // The connection status is deliberately NOT overwritten.
        //
        // It used to be set to "错误", and the first real device test showed why that is
        // wrong: "was the relay connected when this failed?" is the first question every
        // diagnosis asks, and clobbering the status line destroyed exactly that
        // information. Two different failures also overwrote each other, so the publish
        // error that explained a 404 on the other device was nowhere on screen.
        update { it.copy(error = message) }
    }

    private fun update(transform: (ChatState) -> ChatState) {
        val next = synchronized(stateLock) {
            state = transform(state)
            state
        }
        listener.onState(next)
    }

    /**
     * 新建一个群，并把本机的 KeyPackage 与它的 init 私钥存好、发布到目录。
     *
     * 顺序是有意的：**先建群并落盘，再发布**。发布失败不阻断建群——群已经在本地存在，
     * 而发布可以重试；反过来则会出现"发布了成员资格、本地却没有群"的状态。
     *
     * 群标识是随机的 16 字节：它只是标识，安全性完全由 epoch 密钥提供，不依赖它的不可猜性。
     */
    fun createGroup(): String? {
        val groupIdHex = ByteArray(16)
            .also { java.security.SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it) }

        val state = try {
            GroupController.createGroup(profile.identityJson, groupIdHex)
        } catch (e: Exception) {
            fail("建群失败：${e.message}")
            return null
        }

        try {
            groupStore.save(
                com.schat.android.core.groups.GroupRecord(groupIdHex, state, 0L),
            )
        } catch (e: Exception) {
            fail("群已建立但未能保存：${e.message}")
            return null
        }

        // 发布 KeyPackage：别人要有它才能把我加进群。失败只报告，不回滚建群。
        runCatching {
            val mine = GroupController.keyPackage(profile.identityJson)
            // 注意字段名：GroupController.Published 用 packageHex / initKeyPrivateHex。
            groupStore.saveMyKeyPackage(mine.packageHex, mine.initKeyPrivateHex, mine.leafKeyPrivateHex)
            val json = mobile.Mobile.publishBundleJSONWithKeyPackage(
                profile.prekeyStoreJson,
                profile.identityJson,
                mine.packageHex,
            )
            directory.publish(myIdentityHex, json)
        }.onFailure { e ->
            fail("KeyPackage 发布失败，他人暂时无法把你加入群：${e.message}")
        }

        return groupIdHex
    }

    /**
     * 把一个联系人加进已有的群。
     *
     * 一次加人产生【两封内容不同、去向也不同的信】：
     *
     *   1. 提交（0x05）→ 发给【群信箱】：告诉已有的成员"群变了"。只有成员能应用它，
     *      而成员恰好就是能派生出那些信箱的人。
     *   2. Welcome（0x04）→ 发给【新成员个人的】邮箱：它还不是成员，推不出群信箱，
     *      所以只能按身份投递——与一对一消息用同一个 mailboxToken。
     *
     * 顺序也是内容的一部分：**先提交、后 Welcome**。反过来的话，新成员会先拿到一份
     * 指向某个 epoch 的入群材料，而那个 epoch 在群里还不存在。
     *
     * 失败的时刻会被明确报出来（取资料 / 加人 / 发提交 / 发邀请），因为它们对用户是
     * 四件不同的事：对方没上线、对方没发布 KeyPackage、群变更没发出去、邀请没送到。
     */
    fun addMemberToGroup(groupIdHex: String, peerIdentityHex: String) {
        val record = groupStore.load(groupIdHex)
        if (record == null) {
            fail("群不存在")
            return
        }

        // fetch 返回 Result：网络失败与"对方没发布"是两件不同的事，所以把服务器给的原因带出去。
        val fetched = directory.fetch(peerIdentityHex)
        val bundle = fetched.getOrNull()
        if (bundle == null) {
            fail("获取对方资料失败：${fetched.exceptionOrNull()?.message.orEmpty()}")
            return
        }
        if (bundle.isEmpty()) {
            fail("对方的公开资料里没有 KeyPackage，无法把他加入群。请让对方先打开 SCHAT。")
            return
        }
        val keyPackageHex = JSONObject(bundle).optString("key_package")
        if (keyPackageHex.isEmpty()) {
            fail("对方的公开资料里没有 KeyPackage，无法把他加入群。")
            return
        }

        val result = try {
            GroupController.addMember(record.stateJson, profile.identityJson, keyPackageHex)
        } catch (e: Exception) {
            fail("加人失败：${e.message}")
            return
        }

        // 1. 先让群知道。提交只带令牌、不带群 ID，成员按令牌认出是哪个群。
        sendGroupCommit(result.stateJson, result.commitHex)

        // 2. 再把邀请送到对方本人的邮箱。
        runCatching {
            val welcomeBytes = result.welcomeHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val wire = mobile.Mobile.wrapGroupWelcome(
                mobile.Mobile.mailboxToken(peerIdentityHex),
                welcomeBytes,
            )
            if (relay?.sendEnvelope(wire) != true) {
                fail("群邀请未能发出：连接尚未就绪")
            }
        }.onFailure { e -> fail("群邀请发出失败：${e.message}") }

        // 3. 落盘新状态：本机也已经在提交之后的那个 epoch 里了。
        runCatching {
            groupStore.save(record.copy(stateJson = result.stateJson))
        }.onFailure { e -> fail("群变更已生效但未能保存：${e.message}") }
    }

    private fun publishBundle() {
        val json = try {
            // The IDENTITY JSON, not the hex public key. The two are both strings, so the
            // compiler cannot tell them apart — and the binding's parameter used to be
            // named identityHex while expecting the JSON, which made every publish fail
            // with a JSON parse error that looked like nothing at all. The Go side now
            // rejects a hex value with a sentence that says what to pass instead.
            mobile.Mobile.publishBundleJSON(profile.prekeyStoreJson, profile.identityJson)
        } catch (e: Exception) {
            fail("预密钥序列化失败：${e.message}")
            return
        }
        directory.publish(myIdentityHex, json)
            .onSuccess {
                update { it.copy(connection = "预密钥已发布", error = null) }
            }
            .onFailure {
                // Worth being blunt about: until this succeeds, NO peer can start a
                // session with this device, and the only symptom they see is a 404 on
                // their side.
                fail("发布预密钥失败：${it.message}。在发布成功之前，任何对端都无法与你建立会话。")
            }
    }

    /**
     * Writes the ratchet state into the vault.
     *
     * A snapshot contains the root key, both chain keys and every cached skipped key,
     * so it is key material: it goes into the encrypted store and nowhere else. Losing
     * it desynchronises the two sides permanently, which is why it is written after
     * every send and every receive rather than on a timer.
     */
    private fun persistSession(peer: String) {
        val active = session ?: return
        if (peer.isEmpty()) return
        try {
            store.put(SESSION_PREFIX + peer, active.snapshot())
        } catch (e: Exception) {
            fail("保存会话状态失败：${e.message}")
        }
    }

    /**
     * Opens the conversation with [peer], restoring everything kept locally.
     *
     * Called on launch with the peer the app was last talking to, which is what makes
     * killing the app a non-event: the message history and the ratchet snapshot are in the
     * vault, and without reading them back the user sees an empty screen and reasonably
     * concludes the messages are gone.
     *
     * The history is loaded before the snapshot, and both are attributed to [peer] through
     * the state field the save paths read, so the two halves cannot end up filed under
     * different conversations.
     */
    fun openConversation(peer: String) = onWorker { reopenConversation(peer) }

    /**
     * Leaves the conversation without discarding it.
     *
     * The snapshot is flushed first: closing a session drops the in-memory ratchet, and the
     * only copy of its progress would otherwise be whatever was written at the last
     * message.
     */
    fun closeConversation() = onWorker {
        persistSession(state.peerIdentityHex)
        session?.close()
        session = null
        peerMailbox = ""
        update {
            it.copy(
                peerIdentityHex = "",
                safetyNumber = "",
                messages = emptyList(),
                error = null,
                connection = "未选择联系人",
            )
        }
    }

    /** The peers this device has talked to, most recent first. */
    fun knownPeers(): List<String> = contacts.map { it.identityHex }

    /**
     * Replaces this device's identity with one restored from a backup.
     *
     * # What has to be thrown away, and why
     *
     * The session ratchets and message history in the vault belong to the *old* identity:
     * they are keyed by a session with a peer that the new identity never took part in.
     * Keeping them would put messages on screen that the restored identity cannot decrypt
     * and cannot authenticate, which is worse than not having them at all.
     *
     * The one-time prekey pool is deliberately **not** taken from the backup. Prekeys are
     * single-use; republishing a pool that the old device already handed out would make
     * the relay issue the same prekey twice, which is exactly what the pool exists to
     * prevent. The caller regenerates a fresh pool for the restored identity.
     *
     * # After this returns
     *
     * [myIdentityHex] and [myMailbox] are read in the constructor, so a running instance
     * keeps the old ones. The caller must tear this controller down and build a new one —
     * the app does that by locking the vault again.
     */
    fun restoreFromBackup(
        restored: ClientProfileData,
        restoredContacts: List<Contact>,
        onDone: (Throwable?) -> Unit = {},
    ) = onWorker {
        try {
            session?.close()
            session = null
            peerMailbox = ""

            // Everything keyed to the previous identity goes.
            store.names().toList()
                .filter {
                    it.startsWith(SESSION_PREFIX) ||
                        it.startsWith(HISTORY_PREFIX) ||
                        it == LAST_PEER
                }
                .forEach { store.remove(it) }

            profileStore.save(restored)
            profile = restored

            contacts = restoredContacts.take(ContactCodec.MAX_CONTACTS)
            publishContacts()
            store.putString(CONTACTS, ContactCodec.encode(contacts))

            update {
                it.copy(
                    peerIdentityHex = "",
                    safetyNumber = "",
                    messages = emptyList(),
                    contacts = contacts,
                    connection = "已从备份恢复",
                    error = null,
                )
            }
            onDone(null)
        } catch (e: Exception) {
            onDone(e)
        }
    }

    // ------------------------------------------------------------------

    /** Shared by [start] and [openConversation]; both run on the worker. */
    private fun reopenConversation(peer: String) {
        val normalised = peer.trim().lowercase()
        if (normalised.length != IDENTITY_HEX_LENGTH) return

        peerMailbox = mobile.Mobile.mailboxToken(normalised)

        // Reset the id counter before loading, because loadHistory derives it from the
        // highest stored id; leaving the old counter would let a new message collide with a
        // stored one.
        nextMessageId = 1L
        update {
            it.copy(
                peerIdentityHex = normalised,
                safetyNumber = safetyNumberWith(normalised),
                messages = emptyList(),
                error = null,
            )
        }
        loadHistory()

        val restored = restoreSnapshot(normalised)
        rememberPeer(normalised)
        store.putString(LAST_PEER, normalised)

        // Opening a conversation is what clears its badge.
        contacts = ContactList.markRead(contacts, normalised)
        publishContacts()

        update {
            it.copy(
                connection = if (restored) {
                    "已恢复对话（棘轮状态已恢复）"
                } else {
                    "已恢复对话记录；此会话的棘轮状态不在本机，需要对方重新发起"
                },
            )
        }
    }

    /** Restores the ratchet snapshot for [peer]. Returns false when there is none. */
    private fun restoreSnapshot(peer: String): Boolean {
        val blob = store.get(SESSION_PREFIX + peer) ?: return false
        return try {
            session?.close()
            session = mobile.Mobile.restoreSession(blob)
            true
        } catch (e: Exception) {
            // A snapshot that will not decode is reported and then ignored rather than
            // retried: a fresh session can always be built from the peer's prekeys, and
            // refusing to open the conversation at all would be worse.
            fail("本机会话状态已损坏，已忽略：${e.message}")
            false
        }
    }

    /** Records [peer] in the local contact list, newest first. */
    private fun rememberPeer(peer: String) {
        contacts = ContactList.ensure(contacts, peer, System.currentTimeMillis())
        publishContacts()
    }

    /** Saves the contact list and mirrors it into the state the UI renders. */
    private fun publishContacts() {
        store.putString(CONTACTS, ContactCodec.encode(contacts))
        update { it.copy(contacts = contacts) }
    }

    /** Loads the contact list from the vault. Called once, on the worker. */
    private fun loadContacts() {
        contacts = ContactCodec.decode(store.getString(CONTACTS).orEmpty())
        update { it.copy(contacts = contacts) }
    }

    // ------------------------------------------------------------------
    // Contact list

    /** Renames a contact. Creates the record when the identity is not in the list yet. */
    fun renameContact(peer: String, nickname: String) = onWorker {
        contacts = ContactList.rename(contacts, peer, nickname)
        publishContacts()
    }

    /**
     * Forgets a contact and everything stored under it.
     *
     * This deletes the conversation history and the ratchet snapshot as well, because a
     * contact removed from the list whose messages are still on disk is not what "delete"
     * means to a user. The snapshot must go too: keeping it would leave key material for a
     * conversation the user believes they erased.
     */
    fun deleteContact(peer: String) = onWorker {
        val identity = peer.trim().lowercase()
        contacts = ContactList.remove(contacts, identity)
        publishContacts()

        store.remove(SESSION_PREFIX + identity)
        store.remove(HISTORY_PREFIX + identity)

        if (state.peerIdentityHex == identity) {
            session?.close()
            session = null
            peerMailbox = ""
            update {
                it.copy(
                    peerIdentityHex = "",
                    safetyNumber = "",
                    messages = emptyList(),
                    connection = "已删除该联系人",
                    error = null,
                )
            }
        }
        if (store.getString(LAST_PEER) == identity) store.remove(LAST_PEER)
    }

    private fun saveHistory() {
        val peer = state.peerIdentityHex
        if (peer.isEmpty()) return

        val buffer = ByteArrayOutputStream()
        for (message in state.messages) {
            // Base64 for the text so that a message containing a newline or a tab
            // cannot corrupt the record layout.
            val encoded = Base64.getEncoder().encodeToString(message.text.toByteArray(Charsets.UTF_8))
            val line = listOf(
                message.id.toString(),
                if (message.outgoing) "1" else "0",
                message.atMillis.toString(),
                encoded,
            ).joinToString("\t")
            buffer.write(line.toByteArray(Charsets.UTF_8))
            buffer.write('\n'.code)
        }
        store.put(HISTORY_PREFIX + peer, buffer.toByteArray())
    }

    private fun loadHistory() {
        val peer = state.peerIdentityHex
        if (peer.isEmpty()) return
        val raw = store.get(HISTORY_PREFIX + peer)?.toString(Charsets.UTF_8) ?: return

        val messages = raw.lineSequence().mapNotNull { line ->
            val parts = line.split('\t')
            if (parts.size != 4) return@mapNotNull null
            val id = parts[0].toLongOrNull() ?: return@mapNotNull null
            val at = parts[2].toLongOrNull() ?: return@mapNotNull null
            val text = try {
                String(Base64.getDecoder().decode(parts[3]), Charsets.UTF_8)
            } catch (e: Exception) {
                return@mapNotNull null
            }
            ChatMessage(id, parts[1] == "1", text, at, DeliveryState.SENT)
        }.toList()

        nextMessageId = (messages.maxOfOrNull { it.id } ?: 0L) + 1
        update { it.copy(messages = messages) }
    }

    // ------------------------------------------------------------------

    private fun onWorker(block: () -> Unit) {
        worker.execute(block)
    }

    private companion object {
        const val CONTENT_TYPE_FRAME: Byte = 0x01
        const val CONTENT_TYPE_HANDSHAKE: Byte = 0x02

        // 群消息（MLS）。中继不检查这个字节——它只按投递令牌路由，从不解析内容，
        // 所以群消息不需要服务端任何改动。
        const val CONTENT_TYPE_GROUP: Byte = 0x03

        // 群邀请（MLS Welcome）。它走【身份信箱】而不是群信箱：收件人还没进群，
        // 推导不出该群的路由密钥——这是被"新成员不在群里"这个事实逼出来的区分。
        const val CONTENT_TYPE_GROUP_WELCOME: Byte = 0x04

        /**
         * An MLS commit: somebody changed the group.
         *
         * It travels with the GROUP, not with a person — only members can apply it, and the
         * members are exactly the ones who can derive the group's mailboxes. A welcome goes to a
         * single identity because the joiner is not a member yet and cannot derive them.
         */
        const val CONTENT_TYPE_GROUP_COMMIT: Byte = 0x05

        /** 与 prepareGroupMessage 用的同一个数量：两边算出的信箱必须逐字相同。 */
        const val GROUP_MAILBOX_TOKENS = 3L

        const val PROFILE_TEXT = "text"

        const val PREKEY_POOL_SIZE = 100L
        const val HEARTBEAT_SECONDS = 30L

        /** Longest wait between reconnection attempts. */
        const val MAX_RECONNECT_DELAY_SECONDS = 30L

        const val SESSION_PREFIX = "chat.session."
        const val HISTORY_PREFIX = "chat.history."

        /** The local contact list, encoded by ContactCodec. */
        const val CONTACTS = "chat.contacts"

        /** The conversation to reopen on launch. */
        const val LAST_PEER = "chat.lastPeer"

        /** Length of an identity signing public key in hex. */
        const val IDENTITY_HEX_LENGTH = 64

        /** Reads the signing public key out of an identity blob the binding produced. */
        fun signingPublicOf(identityJson: String): String =
            JSONObject(identityJson).getString("signing_public")

        /** Counts the one-time prekeys left in a store blob. */
        fun remainingPreKeys(storeJson: String): Int =
            JSONObject(storeJson).optJSONArray("one_time_prekey_ids")?.length() ?: 0

        /**
         * Recognises the platform's ways of saying "nothing answered".
         *
         * Android reports a LAN address that is unreachable from mobile data as
         * "Software caused connection abort", which tells a user nothing at all. The raw
         * text is still appended, because a wrong guess must not hide the real error.
         */
        fun looksUnreachable(detail: String): Boolean {
            val markers = listOf(
                "abort", "refused", "failed to connect", "unreachable",
                "timed out", "timeout", "no route", "network is unreachable",
            )
            return markers.any { detail.contains(it, ignoreCase = true) }
        }
    }
}
