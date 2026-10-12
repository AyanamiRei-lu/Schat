package com.schat.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// A small, fixed palette. SCHAT has no theming engine and no remote theme: a
// configuration channel that can restyle the UI is also a channel that can be
// used to spoof it.

private val Pine = Color(0xFF0B3D2E)
private val PineLight = Color(0xFF1E6B52)
private val Mint = Color(0xFF7FD1B0)
private val Sand = Color(0xFFF6F3EC)
private val Ink = Color(0xFF101418)
private val InkSurface = Color(0xFF1A2026)
private val Parchment = Color(0xFFE6E1D8)

private val LightColors = lightColorScheme(
    primary = Pine,
    onPrimary = Color.White,
    secondary = PineLight,
    onSecondary = Color.White,
    tertiary = Color(0xFF8C5A00),
    background = Sand,
    onBackground = Ink,
    surface = Color.White,
    onSurface = Ink,
)

private val DarkColors = darkColorScheme(
    primary = Mint,
    onPrimary = Ink,
    secondary = PineLight,
    onSecondary = Color.White,
    tertiary = Color(0xFFF2B950),
    background = Ink,
    onBackground = Parchment,
    surface = InkSurface,
    onSurface = Parchment,
)

/**
 * The SCHAT Material 3 theme.
 *
 * Follows the system light/dark setting. There is no in-app override yet; it
 * arrives with the settings screen in step 4.
 */
@Composable
fun SchatTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
