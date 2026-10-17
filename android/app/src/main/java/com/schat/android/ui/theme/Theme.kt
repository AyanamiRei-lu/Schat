package com.schat.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// SCHAT has no theming engine and no remote theme: a configuration channel that can
// restyle the UI is also a channel that can be used to spoof it. Every colour below is
// a fixed token from DesignTokens.kt, and dynamic colour is deliberately NOT used — a
// theme that follows the wallpaper would make the app's appearance depend on something
// the user cannot audit.

private val LightColors = lightColorScheme(
    // Blue is an accent, not a decoration: it appears only on things you can press and on
    // the messages you sent. Everything else is white, grey or black.
    primary = SchatPalette.Blue500,
    onPrimary = SchatPalette.White,
    primaryContainer = SchatPalette.Blue50,
    onPrimaryContainer = SchatPalette.Blue700,

    secondary = SchatPalette.Gray700,
    onSecondary = SchatPalette.White,
    secondaryContainer = SchatPalette.GrayFill,
    onSecondaryContainer = SchatPalette.Ink,

    tertiary = SchatPalette.Gray600,
    onTertiary = SchatPalette.White,
    tertiaryContainer = SchatPalette.GrayFill,
    onTertiaryContainer = SchatPalette.Ink,

    background = SchatPalette.White,
    onBackground = SchatPalette.Ink,

    surface = SchatPalette.White,
    onSurface = SchatPalette.Ink,
    // Fill blocks: incoming bubbles, the composer field, pressed list rows.
    surfaceVariant = SchatPalette.GrayBubble,
    onSurfaceVariant = SchatPalette.Gray600,
    surfaceTint = Color.Transparent,
    surfaceBright = SchatPalette.White,
    surfaceDim = SchatPalette.GrayFill,
    surfaceContainerLowest = SchatPalette.White,
    surfaceContainerLow = SchatPalette.GrayFill,
    surfaceContainer = SchatPalette.GrayFill,
    surfaceContainerHigh = SchatPalette.GrayBubble,
    surfaceContainerHighest = SchatPalette.GrayBubble,
    inverseSurface = SchatPalette.Ink,
    inverseOnSurface = SchatPalette.Parchment,

    // One hairline grey, used for every divider and outline in the app.
    outline = SchatPalette.Line,
    outlineVariant = SchatPalette.Line,

    error = SchatPalette.Red500,
    onError = SchatPalette.White,
    errorContainer = SchatPalette.RedContainerLight,
    onErrorContainer = SchatPalette.Red500,

    scrim = SchatPalette.Black,
)

private val DarkColors = darkColorScheme(
    primary = SchatPalette.Blue400,
    onPrimary = SchatPalette.Black,
    primaryContainer = SchatPalette.BlueNight,
    onPrimaryContainer = SchatPalette.Blue100,

    secondary = SchatPalette.ParchmentDim,
    onSecondary = SchatPalette.Black,
    secondaryContainer = SchatPalette.BlackFill,
    onSecondaryContainer = SchatPalette.Parchment,

    tertiary = SchatPalette.ParchmentDim,
    onTertiary = SchatPalette.Black,
    tertiaryContainer = SchatPalette.BlackFill,
    onTertiaryContainer = SchatPalette.Parchment,

    background = SchatPalette.Black,
    onBackground = SchatPalette.Parchment,

    surface = SchatPalette.Black,
    onSurface = SchatPalette.Parchment,
    surfaceVariant = SchatPalette.GrayBubbleDark,
    onSurfaceVariant = SchatPalette.ParchmentDim,
    surfaceTint = Color.Transparent,
    surfaceBright = SchatPalette.BlackFill,
    surfaceDim = SchatPalette.Black,
    surfaceContainerLowest = SchatPalette.Black,
    surfaceContainerLow = SchatPalette.BlackFill,
    surfaceContainer = SchatPalette.BlackFill,
    surfaceContainerHigh = SchatPalette.GrayBubbleDark,
    surfaceContainerHighest = SchatPalette.GrayBubbleDark,
    inverseSurface = SchatPalette.Parchment,
    inverseOnSurface = SchatPalette.Ink,

    outline = SchatPalette.LineDark,
    outlineVariant = SchatPalette.LineDark,

    error = SchatPalette.Red500,
    onError = SchatPalette.White,
    errorContainer = SchatPalette.RedContainerDark,
    onErrorContainer = SchatPalette.Red500,

    scrim = SchatPalette.Black,
)

/**
 * Typography.
 *
 * # Why this is deliberately plain
 *
 * An earlier revision used tight negative tracking, heavier weights and a large display
 * scale — the "every heading is a poster" look. QQ and X both set their headings only a
 * little larger than body text and let weight and colour do the work, which is what this
 * scale does: headings stay near body size, body text gets enough line height to read.
 *
 * There is no bundled typeface. A font would be one more binary in a security-sensitive
 * APK, and the project's own rule is that anything shipped can be checked; the system
 * font is something the platform already vouches for.
 *
 * Monospace is not decoration — identity keys, safety numbers and the recovery phrase are
 * compared character by character, and a proportional font makes that harder to do right.
 */
private val SchatTypography = Typography(
    displayLarge = TextStyle(fontSize = 34.sp, lineHeight = 42.sp, fontWeight = FontWeight.SemiBold),
    displayMedium = TextStyle(fontSize = 30.sp, lineHeight = 38.sp, fontWeight = FontWeight.SemiBold),
    displaySmall = TextStyle(fontSize = 26.sp, lineHeight = 34.sp, fontWeight = FontWeight.SemiBold),
    headlineLarge = TextStyle(fontSize = 23.sp, lineHeight = 30.sp, fontWeight = FontWeight.SemiBold),
    headlineMedium = TextStyle(fontSize = 20.sp, lineHeight = 28.sp, fontWeight = FontWeight.SemiBold),
    headlineSmall = TextStyle(fontSize = 18.sp, lineHeight = 26.sp, fontWeight = FontWeight.SemiBold),
    titleLarge = TextStyle(fontSize = 17.sp, lineHeight = 24.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = TextStyle(fontSize = 15.5.sp, lineHeight = 22.sp, fontWeight = FontWeight.Medium),
    titleSmall = TextStyle(fontSize = 14.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium),
    bodyLarge = TextStyle(fontSize = 16.sp, lineHeight = 24.sp, fontWeight = FontWeight.Normal),
    bodyMedium = TextStyle(fontSize = 14.5.sp, lineHeight = 22.sp, fontWeight = FontWeight.Normal),
    bodySmall = TextStyle(fontSize = 13.sp, lineHeight = 19.sp, fontWeight = FontWeight.Normal),
    labelLarge = TextStyle(fontSize = 14.5.sp, lineHeight = 20.sp, fontWeight = FontWeight.Medium),
    labelMedium = TextStyle(fontSize = 12.5.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium),
    labelSmall = TextStyle(fontSize = 11.5.sp, lineHeight = 15.sp, fontWeight = FontWeight.Normal),
)

/** The monospace face used for keys, fingerprints and the recovery phrase. */
val MonospaceStyle: FontFamily = FontFamily.Monospace

/** Text drawn on top of solid blue (buttons, outgoing bubbles). */
val OnGradient: Color = Color.White

/** Secondary text drawn on top of solid blue. */
val OnGradientDim: Color = Color(0xD9FFFFFF)

/**
 * The SCHAT Material 3 theme.
 *
 * Follows the system light/dark setting. There is no in-app override yet; it arrives
 * with the settings screen in step 4.
 */
@Composable
fun SchatTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        typography = SchatTypography,
        shapes = SchatShapes.Material,
        content = content,
    )
}
