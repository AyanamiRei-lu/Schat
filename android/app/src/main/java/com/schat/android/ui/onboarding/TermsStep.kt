package com.schat.android.ui.onboarding

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.schat.android.core.legal.LegalDocument
import com.schat.android.core.legal.LegalDocuments
import com.schat.android.ui.legal.LegalScreen
import com.schat.android.ui.legal.LegalUnavailable
import com.schat.android.ui.legal.readAllLegalTexts

/**
 * 引导流程的**第一步**：阅读并确认协议。
 *
 * # 为什么它在最前面
 *
 * 《儿童个人信息保护规则》2.4(b) 要求"在应用安装或首次启动流程中，设置监护人确认
 * 环节"。一个在用户已经生成身份、设完口令之后才出现的确认页，不满足"首次启动"，
 * 而且那时用户已经投入了成本，拒绝的代价被抬高了——这恰恰是确认环节要避免的。
 *
 * # 两个勾选框，不是一个
 *
 * 第一句是每个用户都要同意的（用户协议 + 隐私政策）。第二句只在**使用者是未成年人**
 * 时才适用，所以它单独成一句，由监护人确认。把它们合成一句会让成年用户被迫为一个
 * 与自己无关的声明背书，也会让监护人看不清自己确认的到底是什么。
 *
 * # 文本读不出来时，不允许继续
 *
 * 如果某一份协议读不到（安装损坏、assets 丢失），这个界面**不会**把空字符串交给
 * 用户去"同意"，也不会让按钮可点。同意一份看不见的协议不是同意。
 */
@Composable
fun TermsStep(
    onAccepted: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current

    // 读一次即可：resources 在一次引导里不会变，重读只会让每次重组都做一次 IO。
    val texts = remember { readAllLegalTexts(context) }
    val documents = remember(texts) { LegalDocuments.parseAll(texts) }

    var reading by remember { mutableStateOf<LegalDocument?>(null) }
    var acceptedUserTerms by remember { mutableStateOf(false) }
    var guardianConfirmed by remember { mutableStateOf(false) }

    // 只有"需要确认的文档"全部读出来、且解析成功时，才允许勾选和继续。
    val missing = LegalDocuments.REQUIRING_CONSENT.filter { id ->
        documents.none { it.id == id }
    }

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

    Column(
        modifier = modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        Text("使用前请阅读并同意以下条款")

        if (missing.isNotEmpty()) {
            // 读不出来就说读不出来，并且不放行。空白页配上可点的"同意"是最坏的一种。
            LegalUnavailable("协议文本（${missing.joinToString("、")}）")
            return@Column
        }

        documents.forEach { doc ->
            TextButton(onClick = { reading = doc }) {
                Text("阅读《${doc.title}》（v${doc.version}）")
            }
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { acceptedUserTerms = !acceptedUserTerms }
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = acceptedUserTerms, onCheckedChange = { acceptedUserTerms = it })
            Text("我已阅读并同意《Schat 用户协议》与《Schat 隐私政策》")
        }

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { guardianConfirmed = !guardianConfirmed }
                .padding(vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = guardianConfirmed, onCheckedChange = { guardianConfirmed = it })
            Text(
                "如使用者为未成年人，其监护人已阅读并同意《Schat 儿童个人信息保护规则》" +
                    "，并同意在监护下使用"
            )
        }

        Button(
            onClick = onAccepted,
            // 两个都要勾上。下面那一条不是"可选的礼貌"，它是儿童规则要求监护人做的确认。
            enabled = acceptedUserTerms && guardianConfirmed,
        ) {
            Text("继续")
        }

        Text(
            "《Schat 服务器运营须知》约束的是自行部署服务器的人，因此不需要在这里确认；" +
                "它列在上方供你随时阅读。",
            modifier = Modifier.padding(top = 12.dp),
        )
    }
}
