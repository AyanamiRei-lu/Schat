package com.schat.android.ui.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import com.schat.android.ui.theme.SchatPalette

/** 底边栏的三个页。 */
enum class HomeTab(val label: String) {
    Chats("聊天"),
    Contacts("通讯录"),
    Mine("我的"),
}

/**
 * 底边栏。
 *
 * # 为什么图标是自己画的
 *
 * 这个应用没有引入图标库（`material-icons` 会是一整包资源，而这里只需要三个线框图形），
 * 所以这三个图标用 `Canvas` 画：气泡、人、人。二十行绘制代码，换掉的是一整个依赖。
 *
 * # 为什么未读只画一个点，不写数字
 *
 * 底边栏是导航，不是收件箱；具体有几条未读，进「聊天」一眼就能看到。数字放在这里，
 * 只会让用户在两个地方看同一件事。
 */
@Composable
fun HomeBottomBar(
    current: HomeTab,
    unread: Int,
    onSelect: (HomeTab) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface)) {
        HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)

        Row(
            modifier = Modifier.fillMaxWidth().height(56.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            HomeTab.entries.forEach { tab ->
                TabItem(
                    tab = tab,
                    selected = tab == current,
                    showDot = tab == HomeTab.Chats && unread > 0,
                    onClick = { onSelect(tab) },
                    modifier = Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun TabItem(
    tab: HomeTab,
    selected: Boolean,
    showDot: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val tint by animateColorAsState(
        targetValue = if (selected) {
            MaterialTheme.colorScheme.primary
        } else {
            MaterialTheme.colorScheme.onSurfaceVariant
        },
        animationSpec = tween(120),
        label = "schat-tab-tint",
    )
    val interaction = remember { MutableInteractionSource() }

    Column(
        modifier = modifier
            .fillMaxHeight()
            .clickable(interactionSource = interaction, indication = null, onClick = onClick),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box {
            TabGlyph(tab = tab, tint = tint, modifier = Modifier.size(22.dp))
            if (showDot) {
                Box(
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .offset(x = 5.dp, y = (-2).dp)
                        .size(7.dp)
                        .clip(CircleShape)
                        .background(SchatPalette.RedBadge),
                )
            }
        }
        Text(
            text = tab.label,
            style = MaterialTheme.typography.labelSmall,
            color = tint,
        )
    }
}

/** 三个页的线框图标。尺寸由调用方给的 22dp 决定，所以坐标全部按比例算。 */
@Composable
private fun TabGlyph(tab: HomeTab, tint: Color, modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val stroke = Stroke(width = w * 0.085f, cap = StrokeCap.Round)

        when (tab) {
            HomeTab.Chats -> {
                // 一个圆角气泡加一条小尾巴。
                drawRoundRect(
                    color = tint,
                    topLeft = Offset(w * 0.08f, h * 0.12f),
                    size = Size(w * 0.84f, h * 0.62f),
                    cornerRadius = CornerRadius(w * 0.22f),
                    style = stroke,
                )
                val tail = Path().apply {
                    moveTo(w * 0.30f, h * 0.72f)
                    lineTo(w * 0.30f, h * 0.92f)
                    lineTo(w * 0.46f, h * 0.74f)
                }
                drawPath(tail, color = tint, style = stroke)
            }

            HomeTab.Contacts -> {
                // 头 + 肩。
                drawCircle(
                    color = tint,
                    radius = w * 0.19f,
                    center = Offset(w * 0.5f, h * 0.31f),
                    style = stroke,
                )
                drawArc(
                    color = tint,
                    startAngle = 200f,
                    sweepAngle = 140f,
                    useCenter = false,
                    topLeft = Offset(w * 0.16f, h * 0.52f),
                    size = Size(w * 0.68f, h * 0.52f),
                    style = stroke,
                )
            }

            HomeTab.Mine -> {
                // 比「通讯录」更靠里的一对：头略小、肩略宽，用来区分两个都是"人"的页。
                drawCircle(
                    color = tint,
                    radius = w * 0.16f,
                    center = Offset(w * 0.5f, h * 0.30f),
                    style = stroke,
                )
                drawArc(
                    color = tint,
                    startAngle = 195f,
                    sweepAngle = 150f,
                    useCenter = false,
                    topLeft = Offset(w * 0.11f, h * 0.50f),
                    size = Size(w * 0.78f, h * 0.58f),
                    style = stroke,
                )
            }
        }
    }
}
