package com.codeheadsystems.vault.autofill

import android.app.assist.AssistStructure
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.view.View
import android.view.autofill.AutofillId
import java.security.MessageDigest
import uniffi.vault_android.AppPage

/** An `AssistStructure.ViewNode` as a [StructNode]. */
class ViewNodeAdapter(private val n: AssistStructure.ViewNode) : StructNode<AutofillId> {
    override val autofillId: AutofillId? get() = n.autofillId
    override val webDomain: String? get() = n.webDomain
    override val webScheme: String? get() = n.webScheme
    override val autofillHints: List<String> get() = n.autofillHints?.toList().orEmpty()
    override val htmlTag: String? get() = n.htmlInfo?.tag
    override val htmlAttributes: List<Pair<String, String>>
        get() = n.htmlInfo?.attributes?.map { it.first to it.second }.orEmpty()
    override val inputType: Int get() = n.inputType
    override val isFocused: Boolean get() = n.isFocused
    override val isVisible: Boolean get() = n.visibility == View.VISIBLE
    override val textValue: String? get() = n.autofillValue?.takeIf { it.isText }?.textValue?.toString()
    override val children: List<StructNode<AutofillId>>
        get() = (0 until n.childCount).map { ViewNodeAdapter(n.getChildAt(it)) }

    companion object {
        fun windows(structure: AssistStructure): List<StructNode<AutofillId>> =
            (0 until structure.windowNodeCount).map { ViewNodeAdapter(structure.getWindowNodeAt(it).rootViewNode) }
    }
}

/**
 * A package's signing certificates (docs/android.md, App matching) as the bindings take them: the
 * current signers, and the rotation history for one signer. A failed lookup gives no signers.
 */
object SigningLookup {
    fun of(pm: PackageManager, packageName: String): AppPage {
        val info = try {
            pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
        } catch (_: PackageManager.NameNotFoundException) {
            null
        } ?: return AppPage(packageName, emptyList(), emptyList(), false)
        return if (info.hasMultipleSigners()) {
            AppPage(packageName, info.apkContentsSigners.map(::sha256), emptyList(), true)
        } else {
            AppPage(packageName, info.apkContentsSigners.map(::sha256), info.signingCertificateHistory.map(::sha256), false)
        }
    }

    private fun sha256(s: Signature) =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
}
