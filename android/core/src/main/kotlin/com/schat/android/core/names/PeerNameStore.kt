package com.schat.android.core.names

import com.schat.android.data.store.EncryptedStore

/**
 * 把名字簿存进加密存储。
 *
 * 名字本身不是密钥材料，但它与联系人一样属于「服务器不该知道的东西」，所以它与保险库
 * 里其它记录用同一把钥匙。
 */
class PeerNameStore(private val store: EncryptedStore) {

    /** 读回整本；没有记录时返回空映射。 */
    fun load(): Map<String, String> = PeerNames.decode(store.getString(KEY_NAMES).orEmpty())

    /**
     * 记住一个人的名字。空名字会删除这一条。
     *
     * 读-改-写而不是追加：存储没有「列出所有键」，但这一本是我们自己维护的，体积有上限。
     */
    fun remember(identityHex: String, name: String) {
        val updated = PeerNames.put(load(), identityHex, name)
        if (updated.isEmpty()) {
            store.remove(KEY_NAMES)
        } else {
            store.putString(KEY_NAMES, PeerNames.encode(updated))
        }
    }

    /** 清空整本（恢复备份或清除数据时由上层决定）。 */
    fun clear() {
        store.remove(KEY_NAMES)
    }

    private companion object {
        const val KEY_NAMES = "peers.names"
    }
}
