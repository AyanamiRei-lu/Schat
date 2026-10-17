package com.schat.android.ui.theme

import androidx.compose.ui.graphics.Brush

/**
 * 界面里唯一允许存在的渐变：相机取景框的描边。
 *
 * # 为什么这里只剩一个
 *
 * 早先这一版把渐变用在了页面底、顶栏、按钮、消息气泡、卡片描边和品牌字样上。
 * 那种做法的结果是**每一处都在喊**，反而没有一处值得看。参考 QQ 与 X：
 * 它们几乎不用渐变，层级靠灰度与细分割线分。
 *
 * 取景框是唯一的例外，理由和配色无关：它压在**相机预览**上，而预览的明度是未知的。
 * 纯色描边在浅色画面上会直接消失，蓝→浅蓝的描边在深浅两种画面上都还看得见。
 */
object SchatGradients {

    /**
     * 取景框描边：浅蓝 → 蓝。
     *
     * @param alpha 由调用方给，用于在深色蒙版上保持稳定的对比度。
     */
    fun viewfinder(alpha: Float = 1f): Brush = Brush.linearGradient(
        colors = listOf(
            SchatPalette.Blue400.copy(alpha = alpha),
            SchatPalette.Blue500.copy(alpha = alpha),
        ),
    )
}
