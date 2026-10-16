package com.schat.android.ui.ui

import androidx.compose.animation.Crossfade
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
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
import com.schat.android.ui.theme.SchatGradients
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.theme.rememberAuroraOffset

/**
 * SCHAT 的界面零件。
 *
 * # 这个文件为什么存在
 *
 * 界面代码里原本每一屏都自己写 `Card`、自己写 `Button`、自己决定圆角和内边距。
 * 结果是同一个应用里出现了三种卡片和四种按钮。**现代感大部分来自一致性**——
 * 同样的圆角、同样的间距节奏、同样的动效时长——而不是来自某一个漂亮的效果。
 *
 * # 一条自我约束
 *
 * 这里的每一个动画都只动**颜色、位移或绘制坐标**，不动布局尺寸（唯一的例外是
 * `ProgressBar` 的填充宽度和 `GradientButton` 的高度，两者都是被显式动画的）。
 * 布局尺寸的动画会带来"整屏重排"的抖动，那看起来是卡，不是流畅。
 */

// ------------------------------------------------------------------ 页面底色

/**
 * 全屏渐变底 + 一团缓慢移动的蓝色光斑。
 *
 * 光斑只画在背景层，而且它所在的是一个叶子节点：动画期间只有这个 `Box` 重组，
 * 整棵界面树不动。这就是"动画流畅"在这里的具体含义——不是动画更快，是动画更小。
 *
 * @param aurora 是否画那团蓝光。列表页开着，正文页关掉，避免和正文抢注意力。
 */
@Composable
fun ScreenBackground(
    modifier: Modifier = Modifier,
    dark: Boolean = isSystemInDarkTheme(),
    aurora: Boolean = true,
    content: @Composable BoxScope.() -> Unit,
) {
    val page = if (dark) SchatGradients.pageDark() else SchatGradients.pageLight()
    val base = if (dark) SchatPalette.Black else SchatPalette.White

    Box(modifier = modifier.fillMaxSize().background(base).background(page)) {
        if (aurora) {
            val offset = rememberAuroraOffset()
            val accent = if (dark) SchatPalette.Blue600 else SchatPalette.Blue500

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .drawBehind {
                        drawCircle(
                            brush = Brush.radialGradient(
                                colors = listOf(
                                    accent.copy(alpha = if (dark) 0.30f else 0.16f),
                                    Color.Transparent,
                                ),
                                center = Offset(size.width * offset.x, size.height * offset.y),
                                radius = size.minDimension * 0.78f,
                            ),
                            radius = size.minDimension * 0.78f,
                            center = Offset(size.width * offset.x, size.height * offset.y),
                        )
                    },
            )
        }
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
 * 区块小标题：全大写、加字距的小字，前面带一段渐变小竖条。
 *
 * 大写在这里不是为了"潮"，是为了把"标题"和"正文"分得足够开——中文界面里没有
 * 大小写可用，字距和颜色就是唯一的分层手段。
 */
@Composable
fun SectionLabel(
    text: String,
    modifier: Modifier = Modifier,
    accent: Color = SchatPalette.Blue500,
) {
    Row(
        modifier = modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
    ) {
        Box(
            modifier = Modifier
                .size(width = 3.dp, height = 14.dp)
                .clip(RoundedCornerShape(2.dp))
                .background(Brush.verticalGradient(listOf(accent, accent.copy(alpha = 0.25f)))),
        )
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

// -------------------------------------------------------------------- 卡片

/**
 * 带渐变描边的卡片。
 *
 * 描边只有 1dp，而且渐变是从"几乎看不见"到"淡淡的蓝"——它要做的是让卡片有边界，
 * 不是让卡片有颜色。**卡片上永远不铺大面积渐变**：正文压在上面时，对比度会随位置
 * 变化，那意味着同一段文字在卡片顶部和底部是两个可读性。
 */
@Composable
fun GradientCard(
    modifier: Modifier = Modifier,
    shape: Shape = MaterialTheme.shapes.medium,
    container: Color = MaterialTheme.colorScheme.surface,
    dark: Boolean = isSystemInDarkTheme(),
    borderBrush: Brush? = null,
    contentPadding: Dp = Dimens.Xl,
    elevation: Dp = 2.dp,
    onClick: (() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val lift by animateDpAsState(
        targetValue = if (pressed) elevation / 2 else elevation,
        animationSpec = spring(),
        label = "schat-card-lift",
    )

    val brush = borderBrush
        ?: if (dark) {
            SchatGradients.cardBorderDark(MaterialTheme.colorScheme.outlineVariant)
        } else {
            SchatGradients.cardBorder(MaterialTheme.colorScheme.outlineVariant)
        }

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
            .shadow(lift, shape, clip = false)
            .clip(shape)
            .background(container)
            .border(BorderStroke(1.dp, brush), shape)
            .then(clickable)
            .padding(contentPadding),
        verticalArrangement = Arrangement.spacedBy(Dimens.Md),
        content = content,
    )
}

// -------------------------------------------------------------------- 按钮

/**
 * 渐变主按钮。
 *
 * # 三个刻意的选择
 *
 * 1. **禁用态是褪色的蓝，不是灰到看不见**。用户需要看出"这里有一个按钮，只是现在
 *    还不能点"，而不是觉得这个按钮消失了；
 * 2. **按下时整体下沉 1dp 并缩到 0.985**。这是最便宜的"有反馈"；
 * 3. **文字永远是白色**。蓝底上的白字在渐变两端对比度都够；浅蓝底上用深色字会在
 *    渐变中段变得难读。
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

    val fill = when {
        !enabled && dark -> SchatGradients.disabledDark()
        !enabled -> SchatGradients.disabled()
        dark -> SchatGradients.brandDark()
        else -> SchatGradients.brand()
    }
    val labelColor by animateColorAsState(
        targetValue = if (enabled) OnGradient else OnGradient.copy(alpha = 0.72f),
        animationSpec = tween(180),
        label = "schat-button-label",
    )
    val lift by animateDpAsState(
        targetValue = if (!enabled) 0.dp else if (pressed) 1.dp else 6.dp,
        animationSpec = spring(),
        label = "schat-button-lift",
    )

    Row(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .shadow(lift, SchatShapes.Pill, clip = false)
            .clip(SchatShapes.Pill)
            .background(fill)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            )
            .padding(horizontal = Dimens.Xxl, vertical = Dimens.Md),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // 间距用 padding 给，不用 Arrangement.spacedBy：后者在 leading 为 null 时
        // 仍会占一格，让文字看起来没居中。
        if (leading != null) {
            Box(modifier = Modifier.padding(end = Dimens.Sm)) { leading() }
        }
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            color = labelColor,
            maxLines = 1,
        )
    }
}

/**
 * 次要按钮：透明底 + 蓝字 + 细描边。
 *
 * 它出现在主按钮旁边时，必须明显比主按钮轻——两个同样重的按钮等于没有主次。
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
    val background by animateColorAsState(
        targetValue = when {
            !enabled -> Color.Transparent
            pressed -> SchatPalette.Blue10
            else -> MaterialTheme.colorScheme.surface
        },
        animationSpec = tween(160),
        label = "schat-ghost-fill",
    )

    Row(
        modifier = modifier
            .heightIn(min = 52.dp)
            .clip(SchatShapes.Pill)
            .border(
                BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
                SchatShapes.Pill,
            )
            .background(background)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            )
            .padding(horizontal = Dimens.Xl, vertical = Dimens.Md),
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

/** 顶栏里的文字动作（返回、加人、关闭…）。 */
@Composable
fun BarAction(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val tint by animateColorAsState(
        targetValue = if (pressed) SchatPalette.White40 else OnGradient,
        animationSpec = tween(140),
        label = "schat-bar-action",
    )

    Box(
        modifier = modifier
            .clip(CircleShape)
            .clickable(
                interactionSource = interaction,
                indication = null,
                enabled = enabled,
                onClick = onClick,
            )
            .padding(horizontal = Dimens.Md, vertical = Dimens.Sm),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            color = if (enabled) tint else OnGradientDim.copy(alpha = 0.55f),
            maxLines = 1,
        )
    }
}

// -------------------------------------------------------------------- 顶栏

/**
 * 顶部横幅：渐变底、标题、副标题、左右动作。
 *
 * # 为什么不是 Material3 的 TopAppBar
 *
 * 这里需要"整条横幅是一个渐变"，而不是"一条纯色栏加一个悬浮按钮"。Material3 的
 * 顶栏把颜色和高度都写死在组件里，要它变成渐变反而要绕开它自己的层级。
 */
@Composable
fun ScreenHeader(
    title: String,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
    dark: Boolean = isSystemInDarkTheme(),
    onBack: (() -> Unit)? = null,
    backLabel: String = "返回",
    actions: (@Composable RowScope.() -> Unit)? = null,
    body: (@Composable ColumnScope.() -> Unit)? = null,
) {
    val brush = if (dark) SchatGradients.headerDark() else SchatGradients.header()

    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(brush)
            .padding(
                start = Dimens.Md,
                end = Dimens.Md,
                top = Dimens.Md,
                bottom = Dimens.Lg,
            ),
        verticalArrangement = Arrangement.spacedBy(Dimens.Sm),
    ) {
        if (onBack != null || actions != null) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (onBack != null) {
                    BarAction(text = "‹ $backLabel", onClick = onBack)
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

        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            color = OnGradient,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = Dimens.Xs),
        )

        if (subtitle != null) {
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = OnGradientDim,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(horizontal = Dimens.Xs),
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
}

/** 顶栏里的状态标：一个会呼吸的小圆点 + 一行字。 */
@Composable
fun StatusPill(
    text: String,
    modifier: Modifier = Modifier,
    tone: Color = SchatPalette.Sky400,
) {
    val breath by SchatGradients.breathing(1_800)

    Row(
        modifier = modifier
            .clip(SchatShapes.Pill)
            .background(SchatPalette.White12)
            .padding(horizontal = Dimens.Md, vertical = Dimens.Xs),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(tone.copy(alpha = 0.35f + breath * 0.45f)),
        )
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = OnGradient,
            maxLines = 1,
        )
    }
}

// ------------------------------------------------------------------ 未读角标

/** 圆角胶囊形的未读计数。 */
@Composable
fun UnreadPill(count: Int, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .defaultMinSize(minWidth = 22.dp, minHeight = 22.dp)
            .clip(SchatShapes.Pill)
            .background(SchatGradients.brand())
            .padding(horizontal = 7.dp, vertical = 2.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = if (count > 99) "99+" else count.toString(),
            style = MaterialTheme.typography.labelSmall,
            color = OnGradient,
            fontWeight = FontWeight.Bold,
        )
    }
}

/** 渐变头像底：身份色相 → 主色。里面放一个字母。 */
@Composable
fun GradientAvatar(
    label: String,
    hue: Float,
    modifier: Modifier = Modifier,
    size: Dp = 46.dp,
) {
    // 色相仍然由身份派生（同一个联系人永远是同一个颜色），但饱和度被压到很低，
    // 再渐变到主色——这样头像既"认得出是谁"，又不会把整套白蓝黑配色打散。
    val from = Color.hsv(hue, 0.30f, 0.86f)
    val to = SchatPalette.Blue600

    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(Brush.linearGradient(listOf(from, to))),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label.take(1).uppercase(),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
            color = OnGradient,
        )
    }
}

// -------------------------------------------------------------------- 进度

/**
 * 步骤进度条。
 *
 * 宽度是动画的——这是这个文件里唯一一处被显式动画的**布局**属性。它出现在一屏的
 * 顶部、上方没有任何东西，所以它的变化只影响自己，不会引起整屏重排。
 */
@Composable
fun ProgressBar(
    fraction: Float,
    modifier: Modifier = Modifier,
    dark: Boolean = isSystemInDarkTheme(),
) {
    val target = fraction.coerceIn(0f, 1f)
    val animated by animateFloatAsState(
        targetValue = target,
        animationSpec = tween(420),
        label = "schat-progress",
    )
    val track = if (dark) SchatPalette.BlackSurface else SchatPalette.Blue50

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(6.dp)
            .clip(SchatShapes.Pill)
            .background(track),
    ) {
        if (animated > 0f) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(animated)
                    .height(6.dp)
                    .clip(SchatShapes.Pill)
                    .background(if (dark) SchatGradients.brandDark() else SchatGradients.brand()),
            )
        }
    }
}

// ---------------------------------------------------------------- 品牌标记

/** 渐变的「SCHAT」字样。 */
@Composable
fun GradientWordmark(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.headlineLarge,
) {
    Text(
        text = text,
        modifier = modifier,
        style = style.copy(brush = SchatGradients.brand()),
    )
}

/** 一个渐变圆角方块，里面放一个字母。用作文本标题旁的品牌标记。 */
@Composable
fun GradientLogoMark(
    letter: String = "S",
    modifier: Modifier = Modifier,
    size: Dp = 40.dp,
) {
    Box(
        modifier = modifier
            .size(size)
            .clip(RoundedCornerShape(percent = 34))
            .background(SchatGradients.brand()),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = letter,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
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
        animationSpec = tween(220),
        label = "schat-check",
    )
    val border by animateColorAsState(
        targetValue = if (checked) {
            SchatPalette.Blue500
        } else {
            MaterialTheme.colorScheme.outline
        },
        animationSpec = tween(200),
        label = "schat-check-border",
    )

    Row(
        modifier = modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.medium)
            .selectable(selected = checked, onClick = { onCheckedChange(!checked) })
            .padding(Dimens.Md),
        verticalAlignment = Alignment.Top,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
    ) {
        Box(
            modifier = Modifier
                .padding(top = 2.dp)
                .size(22.dp)
                .clip(CircleShape)
                .background(
                    if (progress > 0f) {
                        SchatGradients.brand()
                    } else {
                        Brush.linearGradient(listOf(Color.Transparent, Color.Transparent))
                    },
                )
                .border(BorderStroke(1.5.dp, border), CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = "✓",
                style = MaterialTheme.typography.labelSmall,
                color = OnGradient.copy(alpha = progress),
                fontWeight = FontWeight.Bold,
            )
        }
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

// ---------------------------------------------------------------- 等宽文本

/** 指纹、公钥、恢复码：等宽 + 可选中 + 浅底。 */
@Composable
fun MonoBlock(
    text: String,
    modifier: Modifier = Modifier,
    container: Color = MaterialTheme.colorScheme.surfaceContainerLow,
) {
    Box(
        modifier = modifier
            .fillMaxWidth()
            .clip(MaterialTheme.shapes.small)
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
            fontWeight = FontWeight.Medium,
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
 * 与滚动位置无关。时长 200ms 是"看得见但等不到"的一档——超过 300ms 的转场，
 * 在用户第二次看到它时就已经变成等待了。
 */
@Composable
fun <T> FadeSwap(
    target: T,
    modifier: Modifier = Modifier,
    durationMillis: Int = 200,
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
