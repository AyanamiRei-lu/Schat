package com.schat.android.app

import android.os.Handler
import android.os.Looper
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.schat.android.chat.ChatController
import com.schat.android.chat.ChatState
import com.schat.android.core.ServerConfig
import com.schat.android.core.crypto.AndroidDeviceKeyProvider
import com.schat.android.core.crypto.GoKeyDeriver
import com.schat.android.core.crypto.KeystoreSeedStore
import com.schat.android.core.crypto.MetadataStore
import com.schat.android.core.crypto.VaultMetadata
import com.schat.android.core.crypto.VaultSession
import com.schat.android.core.onboarding.OnboardingState
import com.schat.android.core.profile.ClientProfileData
import com.schat.android.core.profile.ClientProfileStore
import com.schat.android.data.store.EncryptedStore
import com.schat.android.ui.chat.ChatScreen
import com.schat.android.ui.onboarding.OnboardingScreen
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatGradients
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.FadeSwap
import com.schat.android.ui.ui.GradientButton
import com.schat.android.ui.ui.GradientCard
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel
import com.schat.android.ui.ui.StatusPill
import java.io.File

/**
 * Plaintext storage for the non-secret vault metadata.
 *
 * A small text file rather than SharedPreferences: it keeps the whole vault's on-disk
 * footprint visible in one place, which matters for a security-sensitive format. The
 * contents are not secret — see [VaultMetadata].
 */
class FileMetadataStore(private val file: File) : MetadataStore {

    override fun read(): VaultMetadata? {
        if (!file.exists()) return null
        val fields = try {
            file.readLines()
                .mapNotNull { line ->
                    val eq = line.indexOf('=')
                    if (eq <= 0) null else line.substring(0, eq) to line.substring(eq + 1)
                }
                .toMap()
        } catch (e: Exception) {
            return null
        }

        val salt = fields["salt"] ?: return null
        val profile = fields["profile"] ?: return null
        val verifier = fields["verifier"] ?: return null
        return VaultMetadata(saltHex = salt, profile = profile, verifier = verifier)
    }

    override fun write(metadata: VaultMetadata) {
        file.parentFile?.mkdirs()
        file.writeText(
            "salt=${metadata.saltHex}\nprofile=${metadata.profile}\nverifier=${metadata.verifier}\n"
        )
    }

    override fun clear() {
        if (file.exists()) file.delete()
    }
}

/**
 * The on-disk layout, and the code that turns a passphrase into an open store.
 *
 * Everything lives under the app's private files directory:
 *
 * ```
 * vault-meta.txt     plaintext: salt, Argon2id profile, verifier
 * device-seed.bin    the vault seed, wrapped under a non-exportable Keystore key
 * vault.dat          the encrypted store
 * ```
 *
 * Note that [EncryptedStore] is constructed only after the vault key exists, so the
 * store file is never even opened without it.
 */
class ClientRuntime(private val filesDir: File) {

    private val metaFile = File(filesDir, "vault-meta.txt")
    private val seedFile = File(filesDir, "device-seed.bin")
    private val storeFile = File(filesDir, "vault.dat")

    private val deriver = GoKeyDeriver()

    val metadata: MetadataStore = FileMetadataStore(metaFile)

    val session: VaultSession = VaultSession(
        deriver = deriver,
        deviceKeys = AndroidDeviceKeyProvider(KeystoreSeedStore(seedFile)),
        metadata = metadata,
    )

    /** True when this device has completed setup before. */
    fun hasVault(): Boolean = session.isInitialised

    /** The plaintext metadata file, for diagnostics. */
    fun metadataFile(): File = metaFile

    /** Opens the encrypted store with a freshly derived key. */
    fun openStore(key: com.schat.android.core.crypto.VaultKey): EncryptedStore =
        EncryptedStore(storeFile, key.cipherKey)

    /** Reports whether the device key is held by a dedicated security chip. */
    fun hardwareBacked(): Boolean =
        AndroidDeviceKeyProvider(KeystoreSeedStore(seedFile)).isHardwareBacked()

    /** The protocol core's self-description, for the diagnostics screen. */
    fun protocolName(): String = deriver.protocolName()
}

/** What the root composable should be showing. */
private sealed interface Stage {
    data object Setup : Stage
    data object Locked : Stage

    /**
     * The unlocked application.
     *
     * The open store is carried here rather than rebuilt on demand because the vault key
     * is destroyed as soon as it has been used. [EncryptedStore] copies the cipher key
     * into its own `SecretKeySpec`, so it stays usable after that, and keeping it alive
     * is what lets the chat controller persist ratchet state after every message.
     */
    data class Ready(val profile: ClientProfileData, val store: EncryptedStore) : Stage
}

/**
 * The application root: first-run setup, unlock, or the app.
 *
 * The stage is decided from what is on disk, not from an in-memory flag, so closing
 * the app cannot leave it in a state where a returning user skips the passphrase.
 */
@Composable
fun SchatRoot() {
    val context = LocalContext.current
    val runtime = remember { ClientRuntime(context.filesDir) }

    var stage by remember {
        // Logged because "it went back to setup" is otherwise indistinguishable from
        // "setup never finished": the decisive fact is whether a vault was detected at
        // launch, and whether the metadata file was actually written last time.
        val hasVault = runtime.hasVault()
        android.util.Log.i(
            TAG,
            "launch: filesDir=${context.filesDir} " +
                "metaExists=${runtime.metadataFile().exists()} hasVault=$hasVault",
        )
        mutableStateOf<Stage>(if (hasVault) Stage.Locked else Stage.Setup)
    }
    var error by remember { mutableStateOf<String?>(null) }

    // 三个阶段（引导 / 解锁 / 应用）之间的切换用一个 200ms 的淡入淡出。
    FadeSwap(target = stage) { current ->
        when (current) {
            Stage.Setup -> OnboardingScreen(
                onGenerateIdentity = { generateIdentity() },
                onTermsAccepted = {
                    runCatching {
                        // 明文存储：同意发生在口令设置之前，那时没有可用的加密密钥。
                        val consentStore = com.schat.android.data.store.PlainFileStore(
                            java.io.File(context.filesDir, "legal-consent.txt")
                        )
                        val documents = com.schat.android.core.legal.LegalDocuments.parseAll(
                            com.schat.android.ui.legal.readAllLegalTexts(context)
                        )
                        val needed = documents.filter {
                            it.id in com.schat.android.core.legal.LegalDocuments.REQUIRING_CONSENT
                        }
                        // 有一份读不到或解析不出，就不放行：同意一份看不见的协议不是同意。
                        check(needed.size == com.schat.android.core.legal.LegalDocuments.REQUIRING_CONSENT.size) {
                            "有协议文本读不到，无法记录确认"
                        }
                        com.schat.android.core.legal.LegalConsentStore(consentStore).save(
                            com.schat.android.core.legal.LegalConsent(
                                acceptedVersions = needed.associate { it.id to it.version },
                                acceptedAtMillis = System.currentTimeMillis(),
                            )
                        )
                    }
                },
                onFinished = { state ->
                    completeSetup(runtime, state)
                        .onSuccess { stage = it }
                        // On failure the stage is left alone, so the user stays on the
                        // step they were on with the message visible.
                        .map { }
                },
            )

            Stage.Locked -> UnlockScreen(
                error = error,
                onSubmit = { passphrase ->
                    error = null
                    stage = unlock(runtime, passphrase) { error = it }
                },
            )

            is Stage.Ready -> ChatRoute(profile = current.profile, store = current.store)
        }
    }
}

/** Generates the identity and reports its public signing key for display. */
private fun generateIdentity(): Result<String> = try {
    val identity = mobile.Mobile.generateIdentity()
    Result.success(identity.signingPublic.chunked(8).joinToString(" "))
} catch (e: Exception) {
    Result.failure(e)
}

/**
 * Finishes setup: create the vault, then write the profile into it.
 *
 * The vault is created first because the store cannot be opened without it, and the
 * profile is written second so that a crash in between leaves a readable vault with an
 * incomplete profile rather than a profile nobody can read.
 *
 * Failures are returned rather than swallowed, so the caller can keep the user on the
 * step they were on instead of restarting the flow and discarding their passphrase and
 * recovery code.
 */
private fun completeSetup(
    runtime: ClientRuntime,
    state: OnboardingState,
): Result<Stage.Ready> {
    val server = state.server
        ?: return Result.failure(IllegalStateException("缺少服务器配置"))

    return try {
        runtime.session.create(state.passphrase).use { key ->
            android.util.Log.i(TAG, "vault created, profile=${runtime.session.profile()}")

            val identityJson = mobile.Mobile.identityToJSON(mobile.Mobile.generateIdentity())
            val prekeyJson = mobile.Mobile.createPreKeyStore(identityJson, PREKEY_POOL_SIZE)
            android.util.Log.i(TAG, "identity and prekeys generated (${prekeyJson.length} bytes)")

            val profile = ClientProfileData(
                identityJson = identityJson,
                prekeyStoreJson = prekeyJson,
                routeKeyHex = mobile.Mobile.newRouteKey(),
                recoveryCode = com.schat.android.core.onboarding.RecoveryCode.format(state.recoveryWords),
                serverUri = server.toUri(),
            )

            // The store is opened while the vault key is still alive and handed to the
            // caller, because the chat controller needs it long after this returns.
            val store = runtime.openStore(key)
            ClientProfileStore(store).save(profile)
            android.util.Log.i(TAG, "profile saved; onboarding complete")
            Result.success(Stage.Ready(profile, store))
        }
    } catch (e: Exception) {
        android.util.Log.e(TAG, "setup failed", e)
        Result.failure(e)
    }
}

/** Unlocks the vault and reads the profile. */
private fun unlock(
    runtime: ClientRuntime,
    passphrase: String,
    onError: (String) -> Unit,
): Stage {
    val key = runtime.session.unlock(passphrase)
    if (key == null) {
        onError("口令不正确")
        return Stage.Locked
    }

    return try {
        key.use {
            val profile = ClientProfileStore(runtime.openStore(key)).load()
            if (profile == null) {
                onError("本地资料不完整")
                Stage.Locked
            } else {
                // Opened before the key is destroyed: the store outlives it, and the
                // chat controller needs it to save ratchet state later.
                Stage.Ready(profile, runtime.openStore(key))
            }
        }
    } catch (e: Exception) {
        onError("打开本地数据失败：${e.message}")
        Stage.Locked
    }
}

/** One-time prekeys published for peers to start sessions with. gomobile maps Go's int to Java's long. */
private const val PREKEY_POOL_SIZE = 100L

/** Log tag. Everything needed to diagnose a failed setup is logged under it. */
private const val TAG = "SCHAT"

/** Destroys a vault key once the store has been opened, so it does not linger. */
private inline fun <T> com.schat.android.core.crypto.VaultKey.use(block: (com.schat.android.core.crypto.VaultKey) -> T): T =
    try {
        block(this)
    } finally {
        destroy()
    }

/**
 * The unlocked application: the relay connection and the conversation.
 *
 * The controller is created inside `remember`, so a recomposition does not open a second
 * connection or start a second session, and `onDispose` closes both. Its listener fires
 * on the controller's own background thread, which is why the state update is posted to
 * the main thread instead of written inline.
 */
@Composable
private fun ChatRoute(profile: ClientProfileData, store: EncryptedStore) {
    val parsed = remember(profile.serverUri) { ServerConfig.parse(profile.serverUri) }
    val config = parsed.getOrNull()

    if (config == null) {
        // Reachable when the stored URI was written by a different build. Saying so
        // beats a connection that quietly fails forever with no explanation.
        Text(
            text = "保存的服务器配置无法解析：${parsed.exceptionOrNull()?.message}",
            modifier = Modifier.padding(24.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
        return
    }

    val main = remember { Handler(Looper.getMainLooper()) }
    var state by remember { mutableStateOf(ChatState()) }
    var myIdentity by remember { mutableStateOf("") }

    // 当前打开的群；为 null 时显示单聊界面。
    var openGroup by remember {
        mutableStateOf<com.schat.android.core.groups.GroupRecord?>(null)
    }

    // 界面层次：群列表 → 群会话 → 会话界面。两者都为 false/空时显示会话界面。
    var showGroupList by remember { mutableStateOf(false) }

    // 是否正在从联系人里挑一个人加进当前群。它比群界面更靠前一层：
    // 选人 → 群列表 → 群 → 会话界面。
    var showAddMember by remember { mutableStateOf(false) }

    val controller = remember {
        ChatController(config, store, profile) { next -> main.post { state = next } }
    }

    DisposableEffect(Unit) {
        myIdentity = controller.myIdentity()
        controller.start()
        onDispose { controller.stop() }
    }

    // 群会话：打开时先渲染群界面并返回，单聊界面保持原样。
    // 用早返回而不是包裹 ChatScreen 调用，是为了让这次改动是一处【插入】而不是一次【重排】——
    // 重排一个多行调用会让 diff 无法阅读，也更容易改错。
    // 群列表：从会话界面的「群组」按钮进入。放在群会话分支之前，所以"打开列表"
    // 总是优先于"某个群还开着"。
    if (showGroupList) {
        val groups = com.schat.android.core.groups.GroupStore(store)
        com.schat.android.ui.chat.GroupListScreen(
            groups = groups.list().map { id ->
                val record = groups.load(id)
                val summary = record?.let {
                    runCatching {
                        com.schat.android.chat.GroupController.summary(it.stateJson)
                    }.getOrNull()
                }
                // 负数表示核心读不懂这份快照。仍然列出这个群，而不是让它凭空消失：
                // 一个打不开的群摆在列表里，比一个不存在的群更接近事实。
                com.schat.android.ui.chat.GroupListItem(
                    groupIdHex = id,
                    memberCount = summary?.memberCount ?: -1L,
                    epoch = summary?.epoch ?: -1L,
                )
            },
            onOpen = { id ->
                openGroup = groups.load(id)
                showGroupList = false
            },
            onBack = { showGroupList = false },
        )
        return
    }

    val currentGroup = openGroup
    // 选人加群：从群界面的「加人」进入。已经在该群里的人不出现在候选里——
    // 列出一个必然失败的动作，比不列出它更让人困惑。
    // 选人与群界面都要求已经打开了一个群，所以这里一并判空——否则 currentGroup
    // 在下面几行里是空类型，而它必须非空才能读它的状态。
    if (showAddMember && currentGroup != null) {
        val alreadyIn = runCatching {
            com.schat.android.chat.GroupController.members(currentGroup.stateJson)
                .map { it.identityHex.lowercase() }
                .toSet()
        }.getOrDefault(emptySet())

        com.schat.android.ui.chat.GroupAddMemberScreen(
            candidates = state.contacts
                .filter { it.identityHex.lowercase() !in alreadyIn }
                .map {
                    com.schat.android.ui.chat.GroupAddCandidate(
                        identityHex = it.identityHex,
                        displayName = it.displayName,
                    )
                },
            onPick = { identityHex ->
                controller.addMemberToGroup(currentGroup.groupIdHex, identityHex)
                showAddMember = false
            },
            onBack = { showAddMember = false },
        )
        return
    }

    if (currentGroup != null) {
        // 群里是谁：核心给出身份（界面不解析群状态），本机联系人给出名字。
        //
        // 认得出的用备注名，认不出的用身份缩写——而**不显示"未知"**：一个陌生的身份是一个
        // 事实，用户可能正是要拿它去核对；"未知"则什么也没说。自己那一行标出「我」，因为
        // 一个没有备注的成员与自己看起来会一模一样。
        val memberNames = runCatching {
            com.schat.android.chat.GroupController.members(currentGroup.stateJson).map { member ->
                val name = state.contacts
                    .firstOrNull { it.identityHex.equals(member.identityHex, ignoreCase = true) }
                    ?.displayName
                    ?: com.schat.android.core.contacts.abbreviate(member.identityHex)
                if (member.identityHex.equals(myIdentity, ignoreCase = true)) "$name（我）" else name
            }
        }.getOrDefault(emptyList())

        // 标题由成员拼出来，而不是让用户起名：对一个两三个人的群来说，"我、张三"比"群 1"
        // 或一串标识更有信息量，而且它不会说谎——名单就是群状态里的名单。人多了就截断，
        // 完整名单在标题下一行。
        val groupTitle = if (memberNames.size <= 3) {
            memberNames.joinToString("、")
        } else {
            memberNames.take(3).joinToString("、") + " 等 ${memberNames.size} 人"
        }

        com.schat.android.ui.chat.GroupScreen(
            groupName = groupTitle.ifEmpty { currentGroup.groupIdHex.take(8) + "…" },
            members = memberNames.ifEmpty { listOf("成员名单暂不可用") },
            messages = com.schat.android.core.groups.GroupStore(store)
                .loadMessages(currentGroup.groupIdHex),
            onSend = { text ->
                controller.sendGroup(
                    currentGroup.stateJson,
                    text,
                    currentGroup.generation,
                    currentGroup.groupIdHex,
                )
            },
            // 把当前正在聊天的联系人加进这个群：一条群提交（成员看到群变了）+ 一封 Welcome
            // （发给被加的人本人）。两步都由控制器完成，界面只负责发起。
            onAddMember = {
                // 打开选人界面，而不是直接加当前聊天对象：群可以有不止一个候选，
                // 而"我正在和谁聊天"与"我想把谁加进来"是两件事。
                showAddMember = true
            },
            // 返回会话界面。openGroup 必须能被清空，否则这个界面是一条死胡同。
            onBack = { openGroup = null },
        )
        return
    }

    ChatScreen(
        // 从「选联系人」切到「会话」是一次换屏，用同一个 200ms 淡入淡出。
        // 用状态本身当 key：对端身份变了就是换了一段会话，也应当有这次转场。
        fadeKey = state.peerIdentityHex,
        state = state,
        myIdentity = myIdentity,
        serverUri = profile.serverUri,
        onStartSession = { controller.startSessionWith(it) },
        onSend = { controller.send(it) },
        onOpenConversation = { controller.openConversation(it) },
        onLeaveConversation = { controller.closeConversation() },
        onCreateGroup = {
            // 建群后立刻打开它，用户不必再去列表里找。
            val created = controller.createGroup()
            if (created != null) {
                openGroup = com.schat.android.core.groups.GroupStore(store).load(created)
            }
        },
        onOpenGroups = {
            // 打开群列表，而不是硬开第一个群：在列表存在之前，用户既不能选择打开哪一个，
            // 也无从知道本机到底有几个群。
            showGroupList = true
        },
        onRenameContact = { peer, name -> controller.renameContact(peer, name) },
        onDeleteContact = { controller.deleteContact(it) },
    )
}

/**
 * The unlock prompt shown on every launch after setup.
 *
 * There is no "forgot passphrase" affordance, and there cannot be: the passphrase is
 * the only thing that opens the vault, and the server holds nothing that could help.
 * The screen says so rather than offering a button that would have to lie.
 */
@Composable
private fun UnlockScreen(error: String?, onSubmit: (String) -> Unit) {
    var passphrase by remember { mutableStateOf("") }

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            ScreenHeader(
                title = "解锁 SCHAT",
                subtitle = "口令在本机派生密钥，服务器不保存任何能替你解密的东西。",
                body = {
                    // 这里不放品牌标记：顶栏本身就是品牌渐变，渐变块压在渐变底上会
                    // 糊成一片。要说的是一件事实，那就只用一句话说它。
                    StatusPill(text = "本机数据已加密")
                },
            )

            ContentColumn(gap = Dimens.BlockGap) {
                error?.let { message ->
                    GradientCard(
                        container = MaterialTheme.colorScheme.errorContainer,
                        borderBrush = SchatGradients.alertBorder(),
                    ) {
                        Text(
                            text = message,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                        )
                    }
                }

                GradientCard {
                    SectionLabel("输入口令")
                    OutlinedTextField(
                        value = passphrase,
                        onValueChange = { passphrase = it },
                        label = { Text("口令") },
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(
                            keyboardType = KeyboardType.Password,
                            imeAction = ImeAction.Done,
                        ),
                        modifier = Modifier.fillMaxWidth(),
                    )

                    GradientButton(
                        text = "解锁",
                        onClick = { onSubmit(passphrase) },
                        enabled = passphrase.isNotEmpty(),
                    )
                }

                GradientCard(container = MaterialTheme.colorScheme.surfaceContainerLow) {
                    Text(
                        text = "忘记口令无法找回：服务器不保存任何数据，也没有任何一方能替你解密。" +
                            "如果你抄下了恢复码，可以在重装后用它在另一台设备上恢复。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}
