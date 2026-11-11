package org.peekinqr.peek_in_qr

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.service.quicksettings.TileService

/**
 * Quick Settings Tile service for Peek-in QR.
 *
 * Security & Architecture Invariants:
 * 1. The Tile ONLY opens the scanner; it never scans or executes any action automatically.
 * 2. It sets the entrypoint extra to "tile" to distinguish origin in scan audit reports.
 * 3. Supports Android API 26+ up to API 34+ via startActivityAndCollapse overloads.
 */
class PeekQuickSettingsTileService : TileService() {

    override fun onClick() {
        super.onClick()

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra("entrypoint", "tile")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pendingIntent = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            startActivityAndCollapse(pendingIntent)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }
}
