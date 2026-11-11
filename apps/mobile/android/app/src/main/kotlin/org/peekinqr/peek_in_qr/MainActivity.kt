package org.peekinqr.peek_in_qr

import android.content.Intent
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val CHANNEL = "org.peekinqr.peek_in_qr/platform"
    private var launchEntrypoint: String = "app_icon"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        val entrypoint = intent?.getStringExtra("entrypoint")
        if (!entrypoint.isNullOrEmpty()) {
            launchEntrypoint = entrypoint
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "getLaunchEntrypoint" -> {
                    result.success(launchEntrypoint)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }
}
