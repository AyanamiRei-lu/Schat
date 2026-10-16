package com.schat.android.ui.theme

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color

/**
 * 全应用共用的渐变。
 *
 * # 为什么是渐变的"位置"而不是"颜色"在动
 *
 * 唯一会动的渐变是背景那一层，而且动的是它的**起止坐标**，不是颜色。这样：
 * 每一帧的动画值来自 animation-core（不触发重组），而颜色本身仍是固定令牌，
 * 所以"动画流畅"与"配色可控"不冲突。
 *
 * 所有渐变都是横向或斜向的。竖向渐变在文字下面会让人误以为那是阴影。
 */
object SchatGradients {

    /** 品牌渐变：蓝 → 天蓝。按钮、进度、强调。 */
    fun brand() = Brush.horizontalGradient(
        colors = listOf(SchatPalette.Blue700, SchatPalette.Blue500, SchatPalette.Sky400),
    )

    /** 品牌渐变的深色模式版本（在纯黑上要更亮才看得出是蓝）。 */
    fun brandDark() = Brush.horizontalGradient(
        colors = listOf(SchatPalette.Blue600, SchatPalette.Blue500, SchatPalette.Blue400),
    )

    /** 按钮禁用态：蓝色褪成灰，仍看得出这里是同一个按钮。 */
    fun disabled() = Brush.horizontalGradient(
        colors = listOf(SchatPalette.Gray200, SchatPalette.Gray100),
    )

    /** 深色模式按钮禁用态。 */
    fun disabledDark() = Brush.horizontalGradient(
        colors = listOf(SchatPalette.BlackSurface, SchatPalette.LineDark),
    )

    /** 深色强调：蓝 → 近黑。用在选中行、标题条。 */
    fun deepBlue() = Brush.linearGradient(
        colors = listOf(SchatPalette.Blue700, SchatPalette.Blue600, SchatPalette.Ink),
    )

    /** 自家消息气泡：从主色到深端的斜向渐变。 */
    fun outgoing(alpha: Float) = Brush.linearGradient(
        colors = listOf(
            SchatPalette.Blue500.copy(alpha = alpha),
            SchatPalette.Blue700.copy(alpha = alpha),
        ),
    )

    /** 深色模式自家气泡：更亮的一端，压在纯黑上仍然清楚。 */
    fun outgoingDark(alpha: Float) = Brush.linearGradient(
        colors = listOf(
            SchatPalette.Blue600.copy(alpha = alpha),
            SchatPalette.BlueNightDeep.copy(alpha = alpha),
        ),
    )

    /**
     * 浅色模式的页面底：白 → 极浅蓝。
     *
     * 极淡。它要让人感觉"这张纸是有一点颜色的"，而不是"这个界面是蓝色的"——
     * 底色一旦抢戏，上面所有文字的可读性都要重新算一遍。
     */
    fun pageLight() = Brush.linearGradient(
        colors = listOf(
            SchatPalette.White,
            SchatPalette.White,
            SchatPalette.Blue50,
        ),
    )

    /** 深色模式的页面底：纯黑 → 近黑 → 极深蓝。 */
    fun pageDark() = Brush.linearGradient(
        colors = listOf(
            SchatPalette.Black,
            SchatPalette.BlackSoft,
            SchatPalette.BlueNightDeep,
        ),
    )

    /** 顶部横幅：蓝 → 近黑。文字压在上面时对比度稳定。 */
    fun header() = Brush.horizontalGradient(
        colors = listOf(SchatPalette.Blue700, SchatPalette.Blue600, SchatPalette.Ink),
    )

    /** 深色模式顶部横幅：黑 → 蓝。 */
    fun headerDark() = Brush.horizontalGradient(
        colors = listOf(SchatPalette.Black, SchatPalette.BlueNightDeep, SchatPalette.BlueNight),
    )

    /** 卡片描边：透明 → 蓝（浅）→ 蓝（深）→ 透明。 */
    fun cardBorder(border: Color) = Brush.linearGradient(
        colors = listOf(
            border,
            SchatPalette.Blue500.copy(alpha = 0.38f),
            border,
        ),
    )

    /** 深色模式卡片描边。 */
    fun cardBorderDark(border: Color) = Brush.linearGradient(
        colors = listOf(
            border,
            SchatPalette.Blue400.copy(alpha = 0.34f),
            border,
        ),
    )

    /** 错误卡片描边，用于那条常驻的元数据警告。 */
    fun alertBorder() = Brush.linearGradient(
        colors = listOf(
            SchatPalette.Red300.copy(alpha = 0.40f),
            SchatPalette.Red500.copy(alpha = 0.75f),
            SchatPalette.Red300.copy(alpha = 0.40f),
        ),
    )

    /**
     * 一个 0..1 之间往返的动画值。
     *
     * 它只喂给**绘制坐标**，不喂给颜色，也不参与布局：所以动画期间不会触发重组，
     * 也不会让文字在整像素之间抖动。周期取整秒数，是为了让它看起来像呼吸，
     * 而不是像在加载。
     */
    @Composable
    fun breathing(periodMillis: Int): State<Float> {
        val transition = rememberInfiniteTransition(label = "schat-breathing")
        return transition.animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(durationMillis = periodMillis, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse,
            ),
            label = "schat-breathing-fraction",
        )
    }
}

/**
 * 背景里那团缓慢移动的蓝光的位置。
 *
 * 它只被画在背景层（见 `SurfaceBackground`），而那是一个叶子节点：动画期间只有它
 * 自己重组，整棵界面树不动。周期给得很长，是为了让人**觉得**它没在动——它只是让
 * 这块白色不至于像一张静止的纸。
 */
@Composable
fun rememberAuroraOffset(seed: Float = 0f): Offset {
    val fraction by SchatGradients.breathing(14_000)
    return Offset(
        x = 0.22f + seed + fraction * 0.72f,
        y = 0.16f + (1f - fraction) * 0.5f,
    )
}
