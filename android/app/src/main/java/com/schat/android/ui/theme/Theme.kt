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
    // Blue is the accent, white is the canvas.
    primary = SchatPalette.Blue500,
    onPrimary = SchatPalette.White,
    primaryContainer = SchatPalette.Blue50,
    onPrimaryContainer = SchatPalette.Blue700,
    inversePrimary = SchatPalette.Blue400,

    secondary = SchatPalette.Blue700,
    onSecondary = SchatPalette.White,
    secondaryContainer = SchatPalette.Blue100,
    onSecondaryContainer = SchatPalette.Blue700,

    tertiary = SchatPalette.Sky400,
    onTertiary = SchatPalette.Ink,
    tertiaryContainer = SchatPalette.Blue50,
    onTertiaryContainer = SchatPalette.Blue700,

    background = SchatPalette.White,
    onBackground = SchatPalette.Ink,

    surface = SchatPalette.White,
    onSurface = SchatPalette.Ink,
    // Outgoing bubbles and unread badges sit on this.
    surfaceVariant = SchatPalette.Blue50,
    onSurfaceVariant = SchatPalette.Gray600,
    surfaceTint = SchatPalette.Blue500,
    surfaceBright = SchatPalette.White,
    surfaceDim = SchatPalette.Gray100,
    surfaceContainerLowest = SchatPalette.White,
    surfaceContainerLow = SchatPalette.SurfaceMuted,
    surfaceContainer = SchatPalette.SurfaceMuted,
    surfaceContainerHigh = SchatPalette.Gray100,
    surfaceContainerHighest = SchatPalette.Gray200,
    inverseSurface = SchatPalette.Ink,
    inverseOnSurface = SchatPalette.Parchment,

    outline = SchatPalette.Gray200,
    outlineVariant = SchatPalette.LineLight,

    error = SchatPalette.Red500,
    onError = SchatPalette.White,
    errorContainer = SchatPalette.RedContainerLight,
    onErrorContainer = SchatPalette.Red500,

    scrim = SchatPalette.Black,
)

private val DarkColors = darkColorScheme(
    // Black is the canvas, blue is the accent.
    primary = SchatPalette.Blue400,
    onPrimary = SchatPalette.Ink,
    primaryContainer = SchatPalette.BlueNight,
    onPrimaryContainer = SchatPalette.Blue100,
    inversePrimary = SchatPalette.Blue700,

    secondary = SchatPalette.Blue400,
    onSecondary = SchatPalette.Ink,
    secondaryContainer = SchatPalette.BlueNightDeep,
    onSecondaryContainer = SchatPalette.Blue100,

    tertiary = SchatPalette.Sky400,
    onTertiary = SchatPalette.Ink,
    tertiaryContainer = SchatPalette.BlueNightDeep,
    onTertiaryContainer = SchatPalette.Blue100,

    background = SchatPalette.Black,
    onBackground = SchatPalette.Parchment,

    surface = SchatPalette.BlackSoft,
    onSurface = SchatPalette.Parchment,
    surfaceVariant = SchatPalette.BlackSurface,
    onSurfaceVariant = SchatPalette.ParchmentDim,
    surfaceTint = SchatPalette.Blue400,
    surfaceBright = SchatPalette.BlackSurface,
    surfaceDim = SchatPalette.Black,
    surfaceContainerLowest = SchatPalette.Black,
    surfaceContainerLow = SchatPalette.BlackSoft,
    surfaceContainer = SchatPalette.BlackSoft,
    surfaceContainerHigh = SchatPalette.BlackSurface,
    surfaceContainerHighest = SchatPalette.LineDark,
    inverseSurface = SchatPalette.Parchment,
    inverseOnSurface = SchatPalette.Ink,

    outline = SchatPalette.LineDark,
    outlineVariant = SchatPalette.LineDark,

    error = SchatPalette.Red300,
    onError = SchatPalette.Black,
    errorContainer = SchatPalette.RedContainerDark,
    onErrorContainer = SchatPalette.Red300,

    scrim = SchatPalette.Black,
)

/**
 * Typography.
 *
 * # Why there is no custom font
 *
 * A bundled typeface would be one more binary in a security-sensitive APK, and the
 * project's own rule is that anything shipped can be checked. The system font is
 * something the user's platform already vouches for, so only the *scale* is adjusted
 * here: heavier headings, tighter headline tracking, roomier body text.
 *
 * Monospace is not decoration — identity keys, safety numbers and the recovery phrase
 * are compared character by character, and a proportional font makes that genuinely
 * harder to do correctly.
 */
private val SchatTypography = Typography(
    displayLarge = TextStyle(
        fontSize = 50.sp,
        lineHeight = 58.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-1.4).sp,
    ),
    displayMedium = TextStyle(
        fontSize = 40.sp,
        lineHeight = 48.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.8).sp,
    ),
    displaySmall = TextStyle(
        fontSize = 32.sp,
        lineHeight = 40.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.5).sp,
    ),
    headlineLarge = TextStyle(
        fontSize = 30.sp,
        lineHeight = 38.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.6).sp,
    ),
    headlineMedium = TextStyle(
        fontSize = 25.sp,
        lineHeight = 32.sp,
        fontWeight = FontWeight.Bold,
        letterSpacing = (-0.3).sp,
    ),
    headlineSmall = TextStyle(
        fontSize = 21.sp,
        lineHeight = 28.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    titleLarge = TextStyle(
        fontSize = 19.sp,
        lineHeight = 26.sp,
        fontWeight = FontWeight.SemiBold,
    ),
    titleMedium = TextStyle(
        fontSize = 16.sp,
        lineHeight = 23.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.1.sp,
    ),
    titleSmall = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.1.sp,
    ),
    bodyLarge = TextStyle(
        fontSize = 16.sp,
        lineHeight = 25.sp,
        fontWeight = FontWeight.Normal,
        letterSpacing = 0.15.sp,
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 22.sp,
        fontWeight = FontWeight.Normal,
        letterSpacing = 0.15.sp,
    ),
    bodySmall = TextStyle(
        fontSize = 12.5.sp,
        lineHeight = 19.sp,
        fontWeight = FontWeight.Normal,
        letterSpacing = 0.2.sp,
    ),
    labelLarge = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        fontWeight = FontWeight.SemiBold,
        letterSpacing = 0.3.sp,
    ),
    labelMedium = TextStyle(
        fontSize = 12.sp,
        lineHeight = 16.sp,
        fontWeight = FontWeight.Medium,
        letterSpacing = 0.5.sp,
    ),
    labelSmall = TextStyle(
        fontSize = 11.sp,
        lineHeight = 15.sp,
        fontWeight = FontWeight.Medium,
        letterSpacing = 0.5.sp,
    ),
)

/** The monospace face used for keys, fingerprints and the recovery phrase. */
val MonospaceStyle: FontFamily = FontFamily.Monospace

/** A translucent white, used for text drawn on top of a gradient. */
val OnGradient: Color = Color.White

/** A dimmed white, used for secondary text drawn on top of a gradient. */
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
