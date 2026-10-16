package com.schat.android.ui.onboarding

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
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
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatGradients
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GhostButton
import com.schat.android.ui.ui.GradientButton
import com.schat.android.ui.ui.GradientCard
import com.schat.android.ui.ui.GradientLogoMark
import com.schat.android.ui.ui.MonoBlock
import com.schat.android.ui.ui.ProgressBar
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel
import com.schat.android.ui.ui.StatusPill

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
     * 保存确认记录，并把已确认的版本书写下来。
     *
     * 同意发生在**保险库创建之前**，所以它走 [com.schat.android.data.store.PlainFileStore]
     * 而不是 EncryptedStore：前者不需要口令派生的密钥，而后者需要——那时口令还没设。
     * 这条记录不是秘密（版本号与时间戳），明文存储在这里是正确的选择而不是妥协。
     */
    onTermsAccepted: () -> Result<Unit>,
    onFinished: (OnboardingState) -> Result<Unit>,
) {
    var state by remember { mutableStateOf(OnboardingState()) }
    var error by remember { mutableStateOf<String?>(null) }
    var identityLabel by remember { mutableStateOf("") }

    // The entropy for the recovery code comes from the platform's secure random
    // source, never from the passphrase: the two must be independent, or knowing one
    // would compromise the other.
    val secureRandom = remember { java.security.SecureRandom() }

    val stepCount = OnboardingStep.values().size
    val stepIndex = state.step.ordinal

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            ScreenHeader(
                title = "设置 SCHAT",
                subtitle = "身份、口令与服务器都只在这台设备上生成；服务器不保存任何一项。",
                body = {
                    StatusPill(
                        text = "第 ${stepIndex + 1} / $stepCount 步 · ${state.step.title()}",
                    )
                    ProgressBar(fraction = (stepIndex + 1).toFloat() / stepCount)
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
    SectionLabel("第一步 · 生成身份", accent = SchatPalette.Blue500)

    Text(
        text = "SCHAT 没有账号也没有密码。你的身份是这台设备上生成的一对密钥，" +
            "私钥永远不会离开本机。",
        style = MaterialTheme.typography.bodyMedium,
    )

    if (identityLabel.isEmpty()) {
        GradientButton(text = "生成身份密钥", onClick = onGenerate)
        return
    }

    GradientCard {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
        ) {
            GradientLogoMark(letter = "ID", size = 38.dp)
            Column {
                Text(
                    text = "身份指纹",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    text = "与对方当面核对时，比对的应当是安全码，不是这个指纹。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        MonoBlock(text = identityLabel)
    }

    GradientButton(text = "下一步", onClick = onNext)
}

@Composable
private fun PassphraseStep(onSubmit: (String, String) -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }

    SectionLabel("第二步 · 设置口令", accent = SchatPalette.Blue500)

    Text(
        text = "口令用于加密本机数据库，并与设备的安全芯片共同保护你的密钥。",
        style = MaterialTheme.typography.bodyMedium,
    )

    GradientCard(
        container = MaterialTheme.colorScheme.errorContainer,
        borderBrush = SchatGradients.alertBorder(),
    ) {
        Text(
            text = "⚠️ 没有「找回口令」这回事",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        Text(
            text = "服务器不保存任何数据，忘记口令就意味着数据永久丢失——" +
                "请务必同时抄下下一步的恢复码。",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
    }

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

    GradientButton(
        text = "继续",
        onClick = { onSubmit(passphrase, confirmation) },
        enabled = passphrase.isNotEmpty() && confirmation.isNotEmpty(),
    )
}

@Composable
private fun RecoveryStep(state: OnboardingState, onSubmit: (List<String>) -> Unit) {
    val indices = state.confirmationIndices()
    val inputs = remember(state.step) { mutableStateOf(List(indices.size) { "" }) }

    SectionLabel("第三步 · 抄写恢复码", accent = SchatPalette.Blue500)

    Text(
        text = "请把下面 24 个单词抄在纸上并妥善保管。" +
            "这是换机时唯一能恢复数据的方式，也是唯一能救回忘记口令后的数据的途径。" +
            "不要截图，不要存在手机里。",
        style = MaterialTheme.typography.bodyMedium,
    )

    GradientCard(container = MaterialTheme.colorScheme.surfaceContainerLow) {
        SectionLabel("恢复码 · 24 个单词")
        Text(
            text = RecoveryCode.format(state.recoveryWords),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Medium,
        )
    }

    SectionLabel("确认：请填写下面几个位置的单词")

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

    GradientButton(
        text = "继续",
        onClick = { onSubmit(inputs.value) },
        enabled = inputs.value.all { it.isNotBlank() },
    )
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

    SectionLabel("最后一步 · 配置服务器", accent = SchatPalette.Blue500)

    Text(
        text = "把服务器的连接信息粘贴进来，或扫描另一台已配置好的设备上显示的「服务器连接码」。",
        style = MaterialTheme.typography.bodyMedium,
    )

    MonoBlock(
        text = "格式形如 schat://connect?h=主机&p=端口&fp=证书指纹&ss=1",
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
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    note?.let {
        Text(
            text = it,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }

    Row(horizontalArrangement = Arrangement.spacedBy(Dimens.Md)) {
        GradientButton(
            text = "连接",
            onClick = { onSubmit(raw) },
            enabled = raw.isNotBlank(),
            modifier = Modifier.weight(1f),
        )
        GhostButton(
            text = "扫码",
            onClick = { scanning = true },
            modifier = Modifier.weight(1f),
        )
    }
}
