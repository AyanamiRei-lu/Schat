package com.schat.android.ui.legal

import android.content.Context
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.schat.android.core.legal.LegalDocument
import com.schat.android.core.legal.LegalDocuments
import com.schat.android.ui.chat.MetadataWarning

/**
 * 读取一份协议的全文。
 *
 * 文本来自 `assets/legal/`，那是 `docs/legal/` 的逐字节副本（CI 里有一条检查保证
 * 两者相同）。读不到就返回 null，调用方必须把"读不出来"当成一个**要显示给用户的
 * 状态**，不能当成空字符串：一份显示为空白页的协议，比一句"暂时无法读取"更糟。
 */
fun readLegalText(context: Context, fileName: String): String? =
    runCatching {
        context.assets.open("${LegalDocuments.DIR}/$fileName").bufferedReader().use { it.readText() }
    }.getOrNull()

/**
 * 把全部四份协议读进内存。
 *
 * 返回 `id -> 全文`。缺任何一份都会体现在结果里（少一个键），而
 * [LegalDocuments.parseAll] 会因此少解析出一份文档——调用方据此就能发现
 * "有一份协议读不到"，而不是显示四份里有三份的空壳。
 */
fun readAllLegalTexts(context: Context): Map<String, String> =
    LegalDocuments.FILE_NAMES.mapNotNull { (id, fileName) ->
        readLegalText(context, fileName)?.let { id to it }
    }.toMap()

/**
 * 阅读一份协议。
 *
 * # 为什么原样显示，不做 Markdown 渲染
 *
 * 这些是**法律文本**，它们的价值在于"你看到的就是我发布的那一份"。一个 Markdown
 * 渲染器会重新解释星号、下划线和缩进——渲染出来的东西与仓库里那份不再逐字相同。
 * 排版难看是可以接受的代价，改动了协议文本则不是。
 *
 * 所以这里直接显示原始字符，只保留换行。
 */
@Composable
fun LegalScreen(
    document: LegalDocument,
    text: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        // 与所有会话界面一致：这条警告常驻且不可关闭。
        MetadataWarning()

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("返回") }
            Text(
                text = "${document.title} v${document.version}",
                modifier = Modifier.weight(1f),
            )
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                // 滚动由调用方提供：这里再加一个 verticalScroll 会构成同方向嵌套，
                // 而 Compose 对此会抛 IllegalStateException（表现为闪退）。
                .padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            Text(text = text)
        }
    }
}

/**
 * 协议列表里的一行。
 *
 * 显示标题与版本，**版本来自文本本身**（见 `LegalDocuments.parse`）——所以这一行
 * 永远不会与它下面那份全文的版本不一致。
 */
@Composable
fun LegalRow(
    document: LegalDocument,
    onOpen: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        TextButton(onClick = onOpen) {
            Text("${document.title}（v${document.version}）")
        }
    }
}

/** 一行提示，用在读取失败时。 */
@Composable
fun LegalUnavailable(what: String) {
    Text(
        text = "无法读取$what。请重新安装应用，或到项目仓库查看对应文本。",
        modifier = Modifier.padding(16.dp),
    )
}


/**
 * 「条款与协议」一节：列出四份文档，点开阅读。
 *
 * 自包含（自己管阅读状态），所以任何界面加一行就能有它——状态页、设置页、关于页。
 *
 * 它读的是**当前**的协议文本，版本号从文本解析而来，所以这一节显示的版本永远不会
 * 与它下面那份全文的版本不一致。
 */
@Composable
fun LegalSection(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val texts = remember { readAllLegalTexts(context) }
    val documents = remember(texts) { LegalDocuments.parseAll(texts) }
    var reading by remember { mutableStateOf<LegalDocument?>(null) }

    val current = reading
    if (current != null) {
        LegalScreen(
            document = current,
            text = texts[current.id].orEmpty(),
            onBack = { reading = null },
            modifier = modifier,
        )
        return
    }

    Column(modifier = modifier) {
        Text("条款与协议")

        if (documents.isEmpty()) {
            // 一份都读不到时说出来，而不是显示一个空的列表——空列表看起来像
            // "这个应用没有任何条款"，那是不对的。
            LegalUnavailable("协议文本")
            return@Column
        }

        documents.forEach { doc ->
            LegalRow(document = doc, onOpen = { reading = doc })
        }
    }
}
