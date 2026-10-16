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
 * # 配色
 *
 * 只用白、蓝、黑三族，加一个红色仅用于**真实的错误状态**（错误提示、失败的消息、
 * 元数据警告）——它是语义色，不是装饰色。所有颜色都是固定值：
 * 这个应用没有主题引擎，也没有远端主题，因为"能重新给界面上色的通道"同时也是
 * "能用来伪装界面的通道"。
 */
object SchatPalette {

    // ---------------------------------------------------------------- 蓝

    /** 主色：品牌蓝。白底上的按钮、强调文字、进度。 */
    val Blue500 = Color(0xFF2563EB)

    /** 主色的深端，用于渐变（白→蓝、蓝→黑都从这里经过）。 */
    val Blue700 = Color(0xFF1D4ED8)

    /** 渐变深端/深色模式主色。 */
    val Blue600 = Color(0xFF1E40AF)

    /** 浅色的蓝，用于深色模式下的主色（在纯黑上要有对比度）。 */
    val Blue400 = Color(0xFF60A5FA)

    /** 天蓝，渐变的亮端。 */
    val Sky400 = Color(0xFF38BDF8)

    /** 极浅蓝，浅色模式下的容器与选中底色。 */
    val Blue50 = Color(0xFFEFF6FF)
    val Blue100 = Color(0xFFDBEAFE)
    val Blue200 = Color(0xFFBFDBFE)

    /** 深色模式下的容器：蓝但很暗，仍读得出是蓝。 */
    val BlueNight = Color(0xFF1E3A8A)
    val BlueNightDeep = Color(0xFF172554)

    /** 半透明的白/蓝，用于叠加在渐变与图片上的浮层。 */
    val White12 = Color(0x1FFFFFFF)
    val White20 = Color(0x33FFFFFF)
    val White40 = Color(0x66FFFFFF)
    val Blue24 = Color(0x3D2563EB)
    val Blue16 = Color(0x292563EB)
    val Blue10 = Color(0x1A2563EB)
    val Blue28 = Color(0x472563EB)

    // ------------------------------------------------------- 白 / 中性

    /** 纯白。浅色模式的背景。 */
    val White = Color(0xFFFFFFFF)

    /** 轻微偏冷的分隔线。纯灰会让白色界面发脏。 */
    val LineLight = Color(0xFFE5E8EF)
    val LineDark = Color(0xFF1F242C)

    /** 浅色模式下的次级表面（卡片落在白底上时，比背景更冷一点）。 */
    val SurfaceMuted = Color(0xFFF6F8FC)
    val OnMutedLight = Color(0xFF4B5563)

    val Gray100 = Color(0xFFEEF1F6)
    val Gray200 = Color(0xFFDFE4EC)
    val Gray500 = Color(0xFF6B7280)
    val Gray600 = Color(0xFF4B5563)

    // ----------------------------------------------------------------- 黑

    /** 纯黑。深色模式的背景——真正的 #000000。 */
    val Black = Color(0xFF000000)

    /** 近黑：深色模式下的卡片，与纯黑背景能分出层次。 */
    val BlackSoft = Color(0xFF0A0D12)
    val BlackSurface = Color(0xFF12161D)

    /** 文字用的近黑。纯黑在白底上略硬，这一档更适合长文。 */
    val Ink = Color(0xFF0B1220)
    val InkSoft = Color(0xFF111827)

    /** 深色模式下的正文色：接近白但不刺眼。 */
    val Parchment = Color(0xFFF3F5F9)
    val ParchmentDim = Color(0xFFA8B0BD)

    // --------------------------------------------------------------- 语义

    /** 错误/失败/警告。唯一允许出现在界面上的非白蓝黑色。 */
    val Red500 = Color(0xFFDC2626)
    val Red300 = Color(0xFFF87171)

    /** 浅色模式错误容器；深色模式另有更暗的一组。 */
    val RedContainerLight = Color(0xFFFFE9E9)
    val RedContainerDark = Color(0xFF3A1414)
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
    val ScreenHorizontal = 20.dp

    /** 屏幕内容的垂直内边距。 */
    val ScreenVertical = 24.dp

    /** 两个区块之间的距离。 */
    val BlockGap = 16.dp

    /** 列表行之间的间隙。 */
    val RowGap = 10.dp
}

/**
 * 圆角。
 *
 * 比 Material3 的默认值更大：这是"现代"这个要求里最省事、也最不容易做错的一件事。
 *
 * 组件**不读** [MaterialShapes] 之外的东西：`MaterialTheme.shapes` 的类型是 Material3
 * 自己的 `Shapes`，自定义属性挂不上去，所以需要胶囊形的地方显式引用 [Pill]，
 * 其余走 [Material] 里那几档。
 */
object SchatShapes {

    /** 小元素：徽标、标签。 */
    val Small = RoundedCornerShape(10.dp)

    /** 卡片与输入框。 */
    val Medium = RoundedCornerShape(18.dp)

    /** 大面板与弹窗。 */
    val Large = RoundedCornerShape(24.dp)

    /** 胶囊：按钮、状态标、头像底。 */
    val Pill = RoundedCornerShape(percent = 50)

    /** Material3 需要的那一份。 */
    val Material = MaterialShapes(
        extraSmall = RoundedCornerShape(8.dp),
        small = Small,
        medium = Medium,
        large = Large,
        extraLarge = RoundedCornerShape(28.dp),
    )
}
