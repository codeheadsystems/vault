package com.codeheadsystems.vault.scan

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.FrameLayout
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import com.codeheadsystems.vault.ui.SecureActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Scans one QR code with CameraX `ImageAnalysis` and ZXing core, and hands its text over through
 * [ScanHandoff], never in the result intent. Only the app's own activities start it; it is not
 * exported.
 */
class ScanActivity : SecureActivity() {
    private lateinit var analysis: ExecutorService
    @Volatile private var done = false

    private val permission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted) start() else finishWith(null)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        analysis = Executors.newSingleThreadExecutor()
        if (checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) start()
        else permission.launch(Manifest.permission.CAMERA)
    }

    private fun start() {
        val previewView = PreviewView(this)
        setContentView(FrameLayout(this).apply { addView(previewView) })
        val decoder = QrDecoder()
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener({
            val provider = future.get()
            val preview = Preview.Builder().build().also { it.surfaceProvider = previewView.surfaceProvider }
            val imageAnalysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            imageAnalysis.setAnalyzer(analysis) { image ->
                image.use {
                    if (done) return@use
                    val plane = it.planes[0]
                    val buffer = plane.buffer
                    val bytes = ByteArray(buffer.remaining()).also { b -> buffer.get(b) }
                    val text = decoder.decode(bytes, plane.rowStride, it.width, it.height)
                    if (text != null) {
                        done = true
                        runOnUiThread { finishWith(text) }
                    }
                }
            }
            try {
                provider.unbindAll()
                provider.bindToLifecycle(this, CameraSelector.DEFAULT_BACK_CAMERA, preview, imageAnalysis)
            } catch (e: IllegalArgumentException) {
                Toast.makeText(this, "No camera", Toast.LENGTH_SHORT).show()
                finishWith(null)
            }
        }, mainExecutor)
    }

    private fun finishWith(text: String?) {
        if (text == null) {
            setResult(RESULT_CANCELED)
        } else {
            ScanHandoff.put(text)
            setResult(RESULT_OK)
        }
        finish()
    }

    override fun onDestroy() {
        if (::analysis.isInitialized) analysis.shutdown()
        super.onDestroy()
    }
}
