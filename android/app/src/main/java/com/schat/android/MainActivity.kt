package com.schat.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.schat.android.app.SchatRoot
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatTheme
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GradientCard
import com.schat.android.ui.ui.GradientLogoMark
import com.schat.android.ui.ui.GradientWordmark
import com.schat.android.ui.ui.KeyValueRow
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel
import com.schat.android.ui.ui.StatusPill

/**
 * It hosts first-run setup, and the build diagnostics screen afterwards.
 *
 * There is still no chat list and no messaging: those arrive in step 5. What this
 * activity must do in the meantime is get a user through onboarding — identity,
 * passphrase and recovery code — and then tell the truth about what the build can do,
 * so that nobody mistakes a working setup screen for a working encrypted messenger.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            SchatTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    SchatRoot()
                }
            }
        }
    }
}

@Composable
private fun BuildStatusScreen(modifier: Modifier = Modifier) {
    ScreenBackground(modifier = modifier) {
        Column(modifier = Modifier.fillMaxSize()) {
            ScreenHeader(
                title = AppInfo.NAME,
                subtitle = stringResource(R.string.status_subtitle),
                body = {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
                    ) {
                        StatusPill(text = "v${AppInfo.VERSION}")
                        StatusPill(text = "minSdk ${AppInfo.MIN_ANDROID}")
                    }
                },
            )

            ContentColumn(gap = Dimens.BlockGap) {
                GradientCard {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
                    ) {
                        GradientLogoMark(letter = "S", size = 44.dp)
                        Column {
                            GradientWordmark(
                                text = AppInfo.NAME,
                                style = MaterialTheme.typography.headlineSmall,
                            )
                            Text(
                                text = "端到端加密聊天 · 服务器只转发密文",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }

                    KeyValueRow(label = "单聊协议", value = AppInfo.PROTOCOL)
                    KeyValueRow(label = "群聊协议", value = AppInfo.GROUP_PROTOCOL)
                }

                StatusCard(
                    title = stringResource(R.string.section_done),
                    entries = AppInfo.implemented,
                    accent = SchatPalette.Blue500,
                )

                StatusCard(
                    title = stringResource(R.string.section_pending),
                    entries = AppInfo.pending,
                    accent = SchatPalette.Red500,
                )

                com.schat.android.ui.legal.LegalSection()

                SecurityNotice()
            }
        }
    }
}

@Composable
private fun StatusCard(
    title: String,
    entries: List<String>,
    accent: Color,
) {
    GradientCard {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
        ) {
            Box(
                modifier = Modifier
                    .size(10.dp)
                    .clip(CircleShape)
                    .background(accent),
            )
            SectionLabel(title, accent = accent)
        }

        entries.forEach { entry ->
            Text(
                text = "· $entry",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
    }
}

@Composable
private fun SecurityNotice() {
    GradientCard(container = MaterialTheme.colorScheme.surfaceContainerLow) {
        SectionLabel(stringResource(R.string.notice_title))
        Text(
            text = stringResource(R.string.notice_body),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Preview(showBackground = true)
@Composable
private fun BuildStatusScreenPreview() {
    SchatTheme {
        Surface(color = MaterialTheme.colorScheme.background) {
            BuildStatusScreen()
        }
    }
}
