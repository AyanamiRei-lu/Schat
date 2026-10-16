package com.schat.android.ui.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.schat.android.core.onboarding.OnboardingState
import com.schat.android.core.onboarding.OnboardingStep
import com.schat.android.core.qr.QrPayload
import com.schat.android.ui.qr.QrScannerScreen
import com.schat.android.core.onboarding.RecoveryCode

/**
 * The first-run flow.
 *
 * Every rule lives in [OnboardingState], in :core, where it is unit tested. This file
 * only renders that state and forwards input, which is deliberately the smallest part
 * of the feature: UI code is the hardest thing in the project to test and the easiest
 * place to hide a security decision by accident.
 *
 * @param onGenerateIdentity produces the long-term identity and returns a short,
 *   human-readable fingerprint of its public key for display. It is a parameter so
 *   that the screen does not depend on the Go core directly, which keeps this file
 *   compilable and reviewable on its own.
 * @param onFinished called with the completed state once every step has been passed.
 *   Returning a failure keeps the user on the current step with the error visible,
 *   rather than throwing them back to the beginning with everything they typed lost.
 */
@Composable
fun OnboardingScreen(
    onGenerateIdentity: () -> Result<String>,
    /**
     * 保存确认记录。
     *
     * # 为什么默认实现是"失败"，而不是一个空操作
     *
     * 同意发生在**保险库创建之前**（口令还没设），所以它不能走 EncryptedStore——
     * 而 `LegalConsentStore` 目前正是那样构造的。这是一个真实的、尚未解决的冲突，
     * 不是遗漏的接线：修法是给 `LegalConsentStore` 一个极小的键值接口，让 `:app`
     * 提供一个明文文件实现（同意记录不是秘密：版本号与时间戳）。
     *
     * 在那之前，默认实现**返回失败**。空操作会让用户以为同意过了而什么都没存，
     * 下次启动又回到这一页，而且失败得无声无息；返回失败会把原因显示出来。
     */
    onTermsAccepted: () -> Result<Unit> = {
        Result.failure(IllegalStateException("条款确认尚未接线：同意记录需要在保险库建立之前保存"))
    },
    onFinished: (OnboardingState) -> Result<Unit>,
    modifier: Modifier = Modifier,
) {
    var state by remember { mutableStateOf(OnboardingState()) }
    var error by remember { mutableStateOf<String?>(null) }
    var identityLabel by remember { mutableStateOf("") }

    // The entropy for the recovery code comes from the platform's secure random
    // source, never from the passphrase: the two must be independent, or knowing one
    // would compromise the other.
    val secureRandom = remember { java.security.SecureRandom() }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "设置 SCHAT",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
        )
        Text(
            text = "第 ${state.step.ordinal + 1} / ${OnboardingStep.values().size} 步 · ${state.step.title()}",
            style = MaterialTheme.typography.bodySmall,
        )

        error?.let { message ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Text(
                    text = message,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
        }

        when (state.step) {
            OnboardingStep.TERMS -> TermsStep(
                onAccepted = {
                    error = null
                    // 先把确认记录落盘，再推进状态机：反过来的话，一次写入失败就会让
                    // 用户"以为同意了"而记录并不存在，下次启动又回到这一页。
                    onTermsAccepted()
                        .mapCatching { state.termsAccepted().getOrThrow() }
                        .onSuccess { state = it }
                        .onFailure { error = it.message ?: "无法保存确认记录" }
                },
            )

            OnboardingStep.IDENTITY -> IdentityStep(
                identityLabel = identityLabel,
                onGenerate = {
                    error = null
                    onGenerateIdentity()
                        .onSuccess { identityLabel = it }
                        .onFailure { error = it.message ?: "生成身份失败" }
                },
                onNext = {
                    state.identityCreated()
                        .onSuccess { state = it }
                        .onFailure { error = it.message }
                },
            )

            OnboardingStep.PASSPHRASE -> PassphraseStep(
                onSubmit = { pass, confirm ->
                    error = null
                    val seed = ByteArray(32).also { secureRandom.nextBytes(it) }
                    state.setPassphrase(pass, confirm, seed)
                        .onSuccess { state = it }
                        .onFailure { error = it.message }
                },
            )

            OnboardingStep.RECOVERY -> RecoveryStep(
                state = state,
                onSubmit = { typed ->
                    error = null
                    val indices = state.confirmationIndices()
                    state.confirmRecovery(indices, typed)
                        .onSuccess { state = it }
                        .onFailure { error = it.message }
                },
            )

            OnboardingStep.SERVER -> ServerStep(
                onSubmit = { raw ->
                    error = null
                    state.setServer(raw)
                        .mapCatching { next ->
                            // Persisting can still fail, for example when the vault
                            // cannot be created on this device. If it does, the step
                            // must not advance: the user has a passphrase and a
                            // recovery code already entered, and restarting the flow
                            // would discard both.
                            onFinished(next).getOrThrow()
                            next
                        }
                        .onSuccess { state = it }
                        .onFailure { error = it.message }
                },
            )

            OnboardingStep.READY -> {
                // The screen is finished; the caller swaps it out. This branch exists
                // only so the when is exhaustive.
                Text("配置完成")
            }
        }
    }
}

private fun OnboardingStep.title(): String = when (this) {
    OnboardingStep.TERMS -> "阅读并同意条款"
    OnboardingStep.IDENTITY -> "生成身份密钥"
    OnboardingStep.PASSPHRASE -> "设置口令"
    OnboardingStep.RECOVERY -> "抄写恢复码"
    OnboardingStep.SERVER -> "配置服务器"
    OnboardingStep.READY -> "完成"
}

@Composable
private fun IdentityStep(
    identityLabel: String,
    onGenerate: () -> Unit,
    onNext: () -> Unit,
) {
    Text(
        text = "SCHAT 没有账号也没有密码。你的身份是这台设备上生成的一对密钥，" +
            "私钥永远不会离开本机。",
        style = MaterialTheme.typography.bodyMedium,
    )

    Button(onClick = onGenerate) { Text("生成身份密钥") }

    if (identityLabel.isNotEmpty()) {
        Card {
            Column(modifier = Modifier.padding(12.dp)) {
                Text("身份指纹", style = MaterialTheme.typography.labelMedium)
                Text(
                    text = identityLabel,
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
        Button(onClick = onNext) { Text("下一步") }
    }
}

@Composable
private fun PassphraseStep(onSubmit: (String, String) -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }

    Text(
        text = "口令用于加密本机数据库，并与设备的安全芯片共同保护你的密钥。",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        text = "⚠️ 没有「找回口令」这回事。服务器不保存任何数据，忘记口令就意味着数据永久丢失——" +
            "请务必同时抄下下一步的恢复码。",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.error,
    )

    OutlinedTextField(
        value = passphrase,
        onValueChange = { passphrase = it },
        label = { Text("口令（至少 10 个字符）") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        modifier = Modifier.fillMaxWidth(),
    )
    OutlinedTextField(
        value = confirmation,
        onValueChange = { confirmation = it },
        label = { Text("再输入一次") },
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
        modifier = Modifier.fillMaxWidth(),
    )

    Button(
        onClick = { onSubmit(passphrase, confirmation) },
        enabled = passphrase.isNotEmpty() && confirmation.isNotEmpty(),
    ) { Text("继续") }
}

@Composable
private fun RecoveryStep(state: OnboardingState, onSubmit: (List<String>) -> Unit) {
    val indices = state.confirmationIndices()
    val inputs = remember(state.step) { mutableStateOf(List(indices.size) { "" }) }

    Text(
        text = "请把下面 24 个单词抄在纸上并妥善保管。",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        text = "这是换机时唯一能恢复数据的方式，也是唯一能救回忘记口令后的数据的途径。" +
            "不要截图，不要存在手机里。",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.error,
    )

    Card {
        Text(
            text = RecoveryCode.format(state.recoveryWords),
            modifier = Modifier.padding(12.dp),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
        )
    }

    Text(
        text = "确认：请填写下面几个位置的单词",
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.Bold,
    )

    indices.forEachIndexed { position, index ->
        OutlinedTextField(
            value = inputs.value[position],
            onValueChange = { value ->
                inputs.value = inputs.value.toMutableList().also { it[position] = value }
            },
            label = { Text("第 ${index + 1} 个单词") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next),
            modifier = Modifier.fillMaxWidth(),
        )
    }

    Button(
        onClick = { onSubmit(inputs.value) },
        enabled = inputs.value.all { it.isNotBlank() },
    ) { Text("继续") }
}

@Composable
private fun ServerStep(onSubmit: (String) -> Unit) {
    var raw by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }

    if (scanning) {
        QrScannerScreen(
            title = "扫描服务器连接二维码",
            hint = "对准另一台已配置好的设备上显示的「服务器连接码」二维码。",
            onResult = { text ->
                scanning = false
                when (QrPayload.parse(text)) {
                    is QrPayload.ServerConfig -> {
                        raw = text.trim()
                        note = null
                    }
                    is QrPayload.Identity ->
                        note = "这是身份码，不是服务器连接码。身份码是在聊天界面扫的。"
                    null ->
                        note = "这个二维码里不是 SCHAT 的连接信息。"
                }
            },
            onCancel = { scanning = false },
        )
        return
    }

    Text(
        text = "把服务器的连接信息粘贴进来，或扫描另一台已配置好的设备上显示的「服务器连接码」。",
        style = MaterialTheme.typography.bodyMedium,
    )
    Text(
        text = "格式形如 schat://connect?h=主机&p=端口&fp=证书指纹&ss=1",
        style = MaterialTheme.typography.bodySmall,
        fontFamily = FontFamily.Monospace,
    )

    OutlinedTextField(
        value = raw,
        onValueChange = { raw = it },
        label = { Text("连接信息") },
        minLines = 2,
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        modifier = Modifier.fillMaxWidth(),
    )

    Text(
        text = "自签名服务器必须带证书指纹（fp 参数）——没有指纹就无法确认连的是正确的服务器，" +
            "应用会拒绝这种配置。",
        style = MaterialTheme.typography.bodySmall,
    )

    note?.let {
        Text(
            text = it,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Button(onClick = { onSubmit(raw) }, enabled = raw.isNotBlank()) { Text("连接") }
        Button(onClick = { scanning = true }) { Text("扫码") }
    }
}
