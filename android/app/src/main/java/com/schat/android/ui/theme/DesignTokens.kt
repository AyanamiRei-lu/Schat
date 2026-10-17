package com.schat.android.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes as MaterialShapes
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * SCHAT 的视觉令牌：颜色、间距、圆角。
 *
 * # 为什么单独成文件
 *
 * 界面代码里原本散落着 `Color(0xFF...)` 与 `12.dp`／`16.dp`／`20.dp` 混用的间距。
 * 同一个应用里，两个界面各自决定"卡片内边距是多少"，最后得到的是不一致，而不是风格。
 * 把决定集中到这里之后，改一次颜色或改一次节奏只有一处要动。
 *
 * # 配色：一个蓝，三档灰，一个红
 *
 * 参考的是 QQ 与 X 这类"用了十年也没过时"的界面，它们的共同点是**克制**：
 *
 * - **蓝色只出现在两处**——可点的东西和用户自己发的消息。它不是装饰，是"这里有动作"的信号；
 * - **层级用灰度分，不用描边、阴影和渐变分**。页面白、填充块浅灰；深色模式页面纯黑、填充块近黑；
 * - **红色只用于真实的错误状态**（错误提示、失败的消息、未读角标、元数据警告）。
 *
 * 早先这一版用过渐变、发光和多彩头像，那类做法的共同问题是"每一处都在喊"，
 * 结果是没有一处值得看。所有颜色都是固定值：这个应用没有主题引擎，也没有远端主题，
 * 因为"能重新给界面上色的通道"同时也是"能用来伪装界面的通道"。
 */
object SchatPalette {

    // ---------------------------------------------------------------- 蓝

    /** 主色。按钮、链接、选中态、自己发出的消息。 */
    val Blue500 = Color(0xFF1A73E8)

    /** 主色的两档深浅，只用于按压态与深色模式下的对比度，**不用于渐变**。 */
    val Blue600 = Color(0xFF1666D6)
    val Blue700 = Color(0xFF1257B8)

    /** 深色模式下的主色：在纯黑上要有对比度。 */
    val Blue400 = Color(0xFF4C9AFF)

    /** 极浅蓝：选中行、次要按钮的底色。 */
    val Blue50 = Color(0xFFEAF2FE)
    val Blue100 = Color(0xFFD7E7FD)

    /** 深色模式下的蓝色填充。 */
    val BlueNight = Color(0xFF10305C)

    /** 半透明浮层：只用在相机预览这类必须是深色的画面上。 */
    val White12 = Color(0x1FFFFFFF)
    val White20 = Color(0x33FFFFFF)
    val White40 = Color(0x66FFFFFF)

    /** 浅色模式下的按压反馈。 */
    val Blue10 = Color(0x141A73E8)

    // ------------------------------------------------------- 白 / 中性

    /** 纯白。浅色模式的页面底色。 */
    val White = Color(0xFFFFFFFF)

    /**
     * 浅灰填充。
     *
     * 用在"填充块"上：输入框、收到的消息气泡、列表里被选中的那一行。
     * QQ 与 X 都靠这一层几乎看不见的灰度分出层级，而不是靠卡片描边加阴影。
     */
    val GrayFill = Color(0xFFF5F6F7)

    /** 输入框与收到的气泡：比 [GrayFill] 再明确一点。 */
    val GrayBubble = Color(0xFFF0F1F3)
    val GrayBubbleDark = Color(0xFF1E2126)

    /** 分割线。1dp，存在感刚好够用。 */
    val Line = Color(0xFFE5E6E8)
    val LineDark = Color(0xFF2A2E33)

    /** 次要文字。 */
    val Gray500 = Color(0xFF8A9099)
    val Gray600 = Color(0xFF5A6069)
    val Gray700 = Color(0xFF3F444B)

    /** 深色模式下的次级填充（卡片、列表行）。 */
    val BlackFill = Color(0xFF16181C)

    // ----------------------------------------------------------------- 黑

    /** 纯黑。深色模式的页面底色——真正的 #000000，和 X 一样。 */
    val Black = Color(0xFF000000)

    /** 正文用的近黑。 */
    val Ink = Color(0xFF0F1419)
    val InkSoft = Color(0xFF111827)

    /** 深色模式下的正文色。 */
    val Parchment = Color(0xFFE7E9EA)
    val ParchmentDim = Color(0xFF8B98A5)

    // --------------------------------------------------------------- 语义

    /** 错误/失败。 */
    val Red500 = Color(0xFFE5484D)

    /** 未读角标。它必须在列表里跳出来，所以用更鲜艳的一档。 */
    val RedBadge = Color(0xFFF5222D)

    /**
     * 在线/已连接。
     *
     * X 用蓝点、QQ 用绿点，两者都是**一个点**而已。这里用绿是因为"已连接"与
     * "这条消息能发出去"是一件事，而蓝点会与"这里能点"的蓝色语义打架。
     */
    val GreenOK = Color(0xFF12B76A)

    /** 浅色模式错误底色；深色模式另有更暗的一组。 */
    val RedContainerLight = Color(0xFFFFF1F0)
    val RedContainerDark = Color(0xFF2A1416)

    /** 元数据警告那条的极浅底：要能看见，但不抢正文。 */
    val AlertFillLight = Color(0xFFFDF4F4)
    val AlertFillDark = Color(0xFF1F1416)
}

/**
 * 间距节奏。
 *
 * 全部是 4 的倍数。界面代码应当只用这一组值，不用裸的 `.dp` 去写内边距——
 * 一个界面里出现 11.dp 和 13.dp 的那种不一致，用户说不出哪里不对，但看得出来。
 */
object Dimens {

    /** 4dp：图标与文字的缝隙。 */
    val Xs = 4.dp

    /** 8dp：同一个组件内部。 */
    val Sm = 8.dp

    /** 12dp：列表行内部。 */
    val Md = 12.dp

    /** 16dp：屏幕水平内边距。 */
    val Lg = 16.dp

    /** 20dp：卡片内边距。 */
    val Xl = 20.dp

    /** 24dp：区块之间。 */
    val Xxl = 24.dp

    /** 32dp：页面顶部与大幅留白。 */
    val Xxxl = 32.dp

    /** 屏幕内容的水平内边距，一处定义，全应用一致。 */
    val ScreenHorizontal = 16.dp

    /** 屏幕内容的垂直内边距。 */
    val ScreenVertical = 16.dp

    /** 两个区块之间的距离。 */
    val BlockGap = 12.dp

    /** 列表行之间的间隙。 */
    val RowGap = 8.dp
}

/**
 * 圆角。
 *
 * **刻意比"现代界面"常见的做法小**：QQ 与 X 的圆角都很克制（8–16dp），
 * 圆角一上 24dp 就开始像卡片贴纸。胶囊只留给按钮与角标。
 *
 * 组件**不读** [MaterialShapes] 之外的东西：`MaterialTheme.shapes` 的类型是 Material3
 * 自己的 `Shapes`，自定义属性挂不上去，所以需要胶囊形的地方显式引用 [Pill]，
 * 其余走 [Material] 里那几档。
 */
object SchatShapes {

    /** 小元素：标签、输入框内的小块。 */
    val Small = RoundedCornerShape(6.dp)

    /** 卡片、消息气泡、弹窗。 */
    val Medium = RoundedCornerShape(12.dp)

    /** 大面板。 */
    val Large = RoundedCornerShape(16.dp)

    /** 胶囊：按钮、状态标、未读角标。 */
    val Pill = RoundedCornerShape(percent = 50)

    /** Material3 需要的那一份。 */
    val Material = MaterialShapes(
        extraSmall = RoundedCornerShape(4.dp),
        small = Small,
        medium = Medium,
        large = Large,
        extraLarge = RoundedCornerShape(20.dp),
    )
}
