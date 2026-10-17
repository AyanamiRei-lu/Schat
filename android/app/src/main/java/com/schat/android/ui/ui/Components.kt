package com.schat.android.ui.ui

import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.OnGradient
import com.schat.android.ui.theme.OnGradientDim
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatShapes

/**
 * SCHAT 的界面零件。
 *
 * # 这一版为什么这么"素"
 *
 * 上一版这里是渐变按钮、渐变描边卡片、渐变头像和会呼吸的状态点。那种界面每一处
 * 都在喊，结果是没有一处值得看——也就是通常说的"AI 味"。改版参考 QQ 与 X：
 *
 * - **页面就是白的**，没有底色渐变、没有光斑；
 * - **层级靠灰度与 1dp 分割线分**，不靠描边加阴影；
 * - **蓝色只标"这里能点"**：主按钮、文字按钮、自己发出的消息、选中态；
 * - **圆角克制**（6/12/16dp），胶囊只给按钮和角标；
 * - **动效只留"按压有反馈、换屏有过渡"**，不再有飘浮、发光、呼吸。
 *
 * # 一条自我约束
 *
 * 这里的动画只动颜色与透明度，不动尺寸与位移。尺寸动画会带来整屏重排，
 * 那看起来是卡，不是流畅。
 */

/** 分割线的颜色，浅色与深色各一档。 */
@Composable
private fun dividerColor(): Color = MaterialTheme.colorScheme.outline

// ------------------------------------------------------------------ 页面底色

/**
 * 整屏底色。就一层纯色：浅色模式纯白，深色模式纯黑。
 *
 * 上一版这里是一层渐变加一团缓慢移动的蓝色光斑。去掉之后界面立刻安静下来，
 * 这也是 QQ 与 X 的共同做法——底色不参与表达。
 */
@Composable
fun ScreenBackground(
    modifier: Modifier = Modifier,
    dark: Boolean = isSystemInDarkTheme(),
    content: @Composable BoxScope.() -> Unit,
) {
    val base = if (dark) SchatPalette.Black else SchatPalette.White

    Box(modifier = modifier.fillMaxSize().background(base)) {
        content()
    }
}

// -------------------------------------------------------------------- 版式

/**
 * 一屏内容的通用容器：水平内边距、区块间距、垂直滚动。
 *
 * 所有屏幕共用它，所以"这一屏的边距是多少"只有一个答案。
 */
@Composable
fun ContentColumn(
    modifier: Modifier = Modifier,
    horizontal: Dp = Dimens.ScreenHorizontal,
    vertical: Dp = Dimens.ScreenVertical,
    gap: Dp = Dimens.BlockGap,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = horizontal, vertical = vertical),
        verticalArrangement = Arrangement.spacedBy(gap),
        content = content,
    )
}

/**
 * 区块小标题。
 *
 * 就是一行小一号的灰字。上一版在它前面加了一段渐变小竖条——那种装饰除了制造
 * "设计感"没有别的作用，去掉之后层级仍然清楚，因为字号和颜色已经把关系说清了。
 *
 * @param accent 保留参数以便调用点不必同时改动；**现在没有视觉效果**。
 */
@Composable
fun SectionLabel(
    text: String,
    modifier: Modifier = Modifier,
    accent: Color = SchatPalette.Blue500,
) {
    Text(
        text = text,
        modifier = modifier,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

// -------------------------------------------------------------------- 卡片

/**
 * 卡片：一层浅灰底 + 12dp 圆角，**没有描边，没有阴影，没有渐变**。
 *
 * QQ 的分组、X 的设置项都是这个做法。卡片的任务是把一组东西框在一起，
 * 描边加阴影会让它变成画面里最重的东西，而它不该是。
 *
 * @param borderBrush 保留参数以便调用点不必同时改动；**现在没有视觉效果**。
 * @param elevation 保留参数；阴影已经取消。
 * @param outlined 需要一条可见边界时（例如落在纯灰底上的卡片）置 true。
 */
@Composable
fun GradientCard(
    modifier: Modifier = Modifier,
    shape: Shape = SchatShapes.Medium,
    container: Color = MaterialTheme.colorScheme.surfaceContainerLow,
    dark: Boolean = isSystemInDarkTheme(),
    @Suppress("UNUSED_PARAMETER") borderBrush: Any? = null,
    contentPadding: Dp = Dimens.Lg,
    @Suppress("UNUSED_PARAMETER") elevation: Dp = 0.dp,
    outlined: Boolean = false,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val pressedFill = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble
    val fill = if (pressed && onClick != null) pressedFill else container

    val clickable = if (onClick != null) {
        Modifier.clickable(
            interactionSource = interaction,
            indication = null,
            onClick = onClick,
        )
    } else {
        Modifier
    }

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(fill)
            .then(
                if (outlined) {
                    Modifier.border(BorderStroke(1.dp, dividerColor()), shape)
                } else {
                    Modifier
                },
            )
            .then(clickable)
            .padding(contentPadding),
        verticalArrangement = Arrangement.spacedBy(Dimens.Sm),
        content = content,
    )
}

// -------------------------------------------------------------------- 按钮

/**
 * 主按钮：实心蓝、白字、44dp 高、10dp 圆角。
 *
 * 没有渐变、没有投影、没有按下沉降。按压反馈只改底色深浅——QQ 和 X 的按钮都只有
 * 这一种反馈，而它足够了。
 */
@Composable
fun GradientButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    dark: Boolean = isSystemInDarkTheme(),
    leading: (@Composable () -> Unit)? = null,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()

    val base = if (dark) SchatPalette.Blue400 else SchatPalette.Blue500
    val pressedColor = if (dark) SchatPalette.Blue500 else SchatPalette.Blue600
    val fill = when {
        !enabled && dark -> SchatPalette.BlackFill
        !enabled -> SchatPalette.GrayBubble
        pressed -> pressedColor
        else -> base
    }
    val label = when {
        !enabled -> MaterialTheme.colorScheme.onSurfaceVariant
        dark -> SchatPalette.Black
        else -> OnGradient
    }

    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp)
            .clip(SchatShapes.Small)
            .background(fill)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            )
            .padding(horizontal = Dimens.Lg, vertical = Dimens.Md),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (leading != null) {
            Box(modifier = Modifier.padding(end = Dimens.Sm)) { leading() }
        }
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            color = label,
            maxLines = 1,
        )
    }
}

/**
 * 次要按钮：透明底 + 蓝字。
 *
 * 它就是一枚文字按钮，没有描边——QQ 与 X 的次要动作都是这个样子。
 * 上一版给它套了一圈胶囊描边，结果两个按钮一样重，等于没有主次。
 */
@Composable
fun GhostButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val fill = when {
        !enabled -> Color.Transparent
        pressed -> SchatPalette.Blue10
        else -> Color.Transparent
    }

    Row(
        modifier = modifier
            .heightIn(min = 44.dp)
            .clip(SchatShapes.Small)
            .background(fill)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            )
            .padding(horizontal = Dimens.Md, vertical = Dimens.Md),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            color = if (enabled) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            },
            maxLines = 1,
        )
    }
}

/**
 * 顶栏里的文字动作（返回、加人、关闭…）。
 *
 * 它画在**纯色**顶栏上，所以用主色；上一版是画在渐变上的白色，现在没有渐变了，
 * 白字压在浅色顶栏上会直接看不见。
 *
 * @param onScrim 压在深色画面上时用白色（只有相机扫码那一屏）。
 */
@Composable
fun BarAction(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    onScrim: Boolean = false,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val fill = if (pressed) SchatPalette.Blue10 else Color.Transparent

    Box(
        modifier = modifier
            .clip(SchatShapes.Small)
            .background(fill)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            )
            .padding(horizontal = Dimens.Sm, vertical = Dimens.Sm),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            color = when {
                !enabled -> MaterialTheme.colorScheme.onSurfaceVariant
                onScrim -> OnGradient
                else -> MaterialTheme.colorScheme.primary
            },
            maxLines = 1,
        )
    }
}

// -------------------------------------------------------------------- 顶栏

/**
 * 顶栏：纯色底、左边返回、右边动作、标题在下、底部一条 1dp 分割线。
 *
 * # 为什么不是渐变横幅
 *
 * 上一版这里是一整条蓝→黑的渐变，所有文字压在上面。那是一眼就能认出的"AI 界面"
 * 特征之一。QQ 的顶栏是纯色，X 的顶栏是白底加一条细线，两者都把注意力留在内容上。
 *
 * @param onScrim 顶栏压在深色画面上时（只有相机扫码那一屏）置 true：底色与分割线都去掉，
 *   文字改白。除此之外的所有界面都用默认的纯色顶栏。
 */
@Composable
fun ScreenHeader(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    onBack: (() -> Unit)? = null,
    backLabel: String = "返回",
    actions: (@Composable RowScope.() -> Unit)? = null,
    body: (@Composable ColumnScope.() -> Unit)? = null,
    onScrim: Boolean = false,
) {
    val titleColor = if (onScrim) OnGradient else MaterialTheme.colorScheme.onSurface
    val subColor = if (onScrim) OnGradientDim else MaterialTheme.colorScheme.onSurfaceVariant

    Column(
        modifier = modifier
            .fillMaxWidth()
            .then(
                if (onScrim) {
                    Modifier
                } else {
                    Modifier.background(MaterialTheme.colorScheme.surface)
                },
            ),
    ) {
        if (onBack != null || actions != null) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 44.dp)
                    .padding(horizontal = Dimens.Sm, vertical = Dimens.Xs),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (onBack != null) {
                    BarAction(
                        text = "‹ $backLabel",
                        onClick = onBack,
                        onScrim = onScrim,
                    )
                }
                Box(modifier = Modifier.weight(1f))
                if (actions != null) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(Dimens.Xs),
                        content = actions,
                    )
                }
            }
        }

        Column(
            modifier = Modifier.padding(
                start = Dimens.Lg,
                end = Dimens.Lg,
                top = if (onBack == null && actions == null) Dimens.Md else Dimens.Xs,
                bottom = Dimens.Md,
            ),
            verticalArrangement = Arrangement.spacedBy(Dimens.Xs),
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                color = titleColor,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )

            if (subtitle != null) {
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = subColor,
                    maxLines = 3,
                    overflow = TextOverflow.Ellipsis,
                )
            }

            if (body != null) {
                Column(
                    modifier = Modifier.padding(top = Dimens.Xs),
                    verticalArrangement = Arrangement.spacedBy(Dimens.Sm),
                    content = body,
                )
            }
        }

        if (!onScrim) {
            HorizontalDivider(thickness = 1.dp, color = dividerColor())
        }
    }
}

/** 状态标：一个小圆点 + 一行灰字。没有底色、没有边框、不闪烁。 */
@Composable
fun StatusPill(
    text: String,
    modifier: Modifier = Modifier,
    tone: Color = SchatPalette.Blue500,
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
    ) {
        Box(
            modifier = Modifier
                .size(6.dp)
                .clip(CircleShape)
                .background(tone),
        )
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            maxLines = 1,
        )
    }
}

// ------------------------------------------------------------------ 未读角标

/** 未读计数：红色胶囊，和 QQ 一样——它必须在列表里跳出来。 */
@Composable
fun UnreadPill(count: Int, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .defaultMinSize(minWidth = 18.dp, minHeight = 18.dp)
            .clip(SchatShapes.Pill)
            .background(SchatPalette.RedBadge)
            .padding(horizontal = 5.dp, vertical = 1.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = if (count > 99) "99+" else count.toString(),
            style = MaterialTheme.typography.labelSmall,
            color = OnGradient,
        )
    }
}

/**
 * 头像：一个纯色圆底加首字母。
 *
 * 色相仍然由身份公钥派生（同一个人永远是同一个颜色，重启和换设备都不变），
 * 但**不再是渐变**，而且饱和度压得很低。
 *
 * 它是装饰，不是标识：两个联系人可能撞色，颜色也不代表任何信任关系。
 * 真正的比对靠安全码，不靠这个颜色。
 */
@Composable
fun GradientAvatar(
    label: String,
    hue: Float,
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    val fill = Color.hsv(hue, 0.22f, 0.84f)

    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(fill),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label.take(1).uppercase(),
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Medium,
            color = OnGradient,
        )
    }
}

// -------------------------------------------------------------------- 进度

/** 步骤进度条：浅灰轨道 + 实心蓝填充。 */
@Composable
fun ProgressBar(
    fraction: Float,
    modifier: Modifier = Modifier,
    dark: Boolean = isSystemInDarkTheme(),
) {
    val target = fraction.coerceIn(0f, 1f)
    val animated by animateFloatAsState(
        targetValue = target,
        animationSpec = tween(300),
        label = "schat-progress",
    )
    val track = if (dark) SchatPalette.BlackFill else SchatPalette.GrayBubble
    val fill = if (dark) SchatPalette.Blue400 else SchatPalette.Blue500

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(3.dp)
            .clip(SchatShapes.Pill)
            .background(track),
    ) {
        if (animated > 0f) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(animated)
                    .height(3.dp)
                    .clip(SchatShapes.Pill)
                    .background(fill),
            )
        }
    }
}

// ---------------------------------------------------------------- 品牌标记

/**
 * 品牌字样：实心蓝，没有渐变。
 *
 * 名字保留 `Gradient` 前缀只是为了不动调用点，它现在不做渐变。
 */
@Composable
fun GradientWordmark(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.headlineLarge,
) {
    Text(
        text = text,
        modifier = modifier,
        style = style,
        color = MaterialTheme.colorScheme.primary,
    )
}

/** 一个纯蓝圆角方块加一个字母，用作文本标题旁的标记。 */
@Composable
fun GradientLogoMark(
    letter: String = "S",
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(SchatShapes.Medium)
            .background(MaterialTheme.colorScheme.primary),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = letter,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Medium,
            color = OnGradient,
        )
    }
}

// ---------------------------------------------------------------- 可选项

/** 选项行：一个圆形勾选标记 + 一段说明文字。整行可点。 */
@Composable
fun CheckOption(
    checked: Boolean,
    text: String,
    onCheckedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val progress by animateFloatAsState(
        targetValue = if (checked) 1f else 0f,
        animationSpec = tween(150),
        label = "schat-check",
    )
    val fill = if (checked) MaterialTheme.colorScheme.primary else Color.Transparent

    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(SchatShapes.Small)
            .selectable(selected = checked, onClick = { onCheckedChange(!checked) })
            .padding(vertical = Dimens.Sm),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
    ) {
        Box(
            modifier = Modifier
                .padding(top = 1.dp)
                .size(20.dp)
                .clip(CircleShape)
                .background(fill)
                .border(BorderStroke(1.5.dp, if (checked) fill else dividerColor()), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            if (progress > 0.5f) {
                Text(
                    text = "✓",
                    style = MaterialTheme.typography.labelSmall,
                    color = OnGradient,
                )
            }
        }
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

// ---------------------------------------------------------------- 等宽文本

/** 指纹、公钥、恢复码：等宽 + 浅灰底。 */
@Composable
fun MonoBlock(
    text: String,
    modifier: Modifier = Modifier,
    container: Color = MaterialTheme.colorScheme.surfaceContainerLow,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(SchatShapes.Small)
            .background(container)
            .padding(Dimens.Md),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** 一行「标签：值」，标签宽度固定，便于上下对齐。 */
@Composable
fun KeyValueRow(
    label: String,
    value: String,
    modifier: Modifier = Modifier,
    labelWidth: Dp = 84.dp,
    monospace: Boolean = true,
) {
    Row(modifier = modifier.fillMaxWidth()) {
        Text(
            text = label,
            modifier = Modifier.width(labelWidth),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** 供调用方读取"现在是不是深色"的便捷别名，避免每个文件都 import 一次。 */
@Composable
fun isDarkNow(): Boolean = isSystemInDarkTheme()

// -------------------------------------------------------------------- 换屏

/**
 * 两屏之间的交叉淡入淡出。
 *
 * # 为什么是淡入而不是滑动
 *
 * 滑动会同时移动两屏，任何一屏里正在滚动的列表都会跟着抖；而淡入淡出只动透明度，
 * 与滚动位置无关。150ms 是"看得见但等不到"的一档——它只是让换屏不显得突兀，
 * 不应该让人等它。
 */
@Composable
fun <T> FadeSwap(
    target: T,
    modifier: Modifier = Modifier,
    durationMillis: Int = 150,
    content: @Composable (T) -> Unit,
) {
    Crossfade(
        targetState = target,
        animationSpec = tween(durationMillis),
        modifier = modifier,
        label = "schat-fade-swap",
        content = content,
    )
}
