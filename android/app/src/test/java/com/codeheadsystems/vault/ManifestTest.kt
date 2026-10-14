package com.codeheadsystems.vault

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element

/**
 * The manifest rules of docs/android.md, checked on the merged manifest of each variant, which
 * includes every library's components.
 */
class ManifestTest {
    private val ns = "http://schemas.android.com/apk/res/android"
    private val intermediates = File(System.getProperty("vault.mergedManifests")!!)
    private val res = File(System.getProperty("vault.sourceManifest")!!).parentFile.resolve("res")

    private fun parse(f: File) = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        .newDocumentBuilder().parse(f).documentElement

    // The app's two variants; the test APK's manifest (debugAndroidTest) is not the app's.
    private val manifests: List<File> = listOf("debug", "release")
        .mapNotNull { variant -> intermediates.resolve("merged_manifest/$variant").walk().firstOrNull { it.name == "AndroidManifest.xml" } }

    private fun Element.all(tag: String): List<Element> {
        val list = getElementsByTagName(tag)
        return (0 until list.length).map { list.item(it) as Element }
    }

    private fun Element.attr(name: String): String? = getAttributeNodeNS(ns, name)?.value

    private val componentTags = listOf("activity", "activity-alias", "service", "receiver", "provider")

    @Test
    fun aMergedManifestExists() {
        assertEquals("the debug and release merged manifests under $intermediates", 2, manifests.size)
    }

    @Test
    fun onlyTheLauncherAndTheAutofillServiceAreExported() {
        for (m in manifests.map(::parse)) {
            val components = componentTags.flatMap { m.all(it) }
            for (c in components) assertNotNull("${c.attr("name")} states no export status", c.attr("exported"))
            val exported = components.filter { it.attr("exported") == "true" }.map { it.attr("name") }.toSet()
            assertEquals(
                setOf("com.codeheadsystems.vault.ui.MainActivity", "com.codeheadsystems.vault.autofill.VaultAutofillService"),
                exported,
            )
            val service = components.single { it.attr("name") == "com.codeheadsystems.vault.autofill.VaultAutofillService" }
            assertEquals("android.permission.BIND_AUTOFILL_SERVICE", service.attr("permission"))
        }
    }

    @Test
    fun noComponentSetsAProcess() {
        for (m in manifests.map(::parse)) {
            val withProcess = (listOf("application") + componentTags).flatMap { m.all(it) }.filter { it.attr("process") != null }
            assertEquals(emptyList<String>(), withProcess.map { it.attr("name") })
        }
    }

    @Test
    fun noDeepLinkAndTheLauncherFilterIsMainAndLauncherOnly() {
        for (m in manifests.map(::parse)) {
            assertEquals("an intent filter has <data>", 0, m.all("data").count { it.parentNode.nodeName == "intent-filter" })
            val main = m.all("activity").single { it.attr("name") == "com.codeheadsystems.vault.ui.MainActivity" }
            val filter = main.all("intent-filter").single()
            assertEquals(listOf("android.intent.action.MAIN"), filter.all("action").map { it.attr("name") })
            assertEquals(listOf("android.intent.category.LAUNCHER"), filter.all("category").map { it.attr("name") })
            val others = componentTags.flatMap { m.all(it) }.filter { it.attr("name")!!.startsWith("com.codeheadsystems") && it != main }
            for (c in others.filter { it.nodeName == "activity" }) assertEquals(0, c.all("intent-filter").size)
        }
    }

    @Test
    fun pickerAndSaveStayOutOfRecents() {
        for (m in manifests.map(::parse)) {
            for (name in listOf("autofill.PickerActivity", "autofill.SaveActivity")) {
                val a = m.all("activity").single { it.attr("name") == "com.codeheadsystems.vault.$name" }
                assertEquals(name, "false", a.attr("exported"))
                assertEquals(name, "true", a.attr("excludeFromRecents"))
                assertEquals(name, "true", a.attr("noHistory"))
            }
        }
    }

    @Test
    fun backupIsOffForEveryAndroidGeneration() {
        for (m in manifests.map(::parse)) {
            val app = m.all("application").single()
            assertEquals("false", app.attr("allowBackup"))
            assertEquals("@xml/backup_rules", app.attr("fullBackupContent"))
            assertNotNull(app.attr("dataExtractionRules"))
            assertNotNull(app.attr("networkSecurityConfig"))
        }
        val full = parse(res.resolve("xml/backup_rules.xml"))
        val extraction = parse(res.resolve("xml/data_extraction_rules.xml"))
        val domains = setOf("root", "file", "database", "sharedpref", "external")
        assertEquals(domains, full.all("exclude").filter { it.getAttribute("path") == "." }.map { it.getAttribute("domain") }.toSet())
        for (section in listOf("cloud-backup", "device-transfer")) {
            val s = extraction.all(section).single()
            assertEquals(section, domains, s.all("exclude").filter { it.getAttribute("path") == "." }.map { it.getAttribute("domain") }.toSet())
            assertEquals(section, 0, s.all("include").size)
        }
    }

    @Test
    fun noQueryAllPackagesAndLauncherQueriesOnly() {
        for (m in manifests.map(::parse)) {
            assertFalse(m.all("uses-permission").any { it.attr("name") == "android.permission.QUERY_ALL_PACKAGES" })
            val queries = m.all("queries").flatMap { it.all("intent") }
            assertEquals(1, queries.size)
        }
    }

    @Test
    fun releaseRefusesAllCleartextAndDebugAllowsLoopbackOnly() {
        val release = parse(res.resolve("xml/network_security_config.xml"))
        assertEquals("false", release.all("base-config").single().getAttribute("cleartextTrafficPermitted"))
        assertEquals(0, release.all("domain-config").size)
        assertEquals(listOf("system"), release.all("certificates").map { it.getAttribute("src") })

        val debug = parse(res.resolve("../../debug/res/xml/network_security_config.xml"))
        assertEquals("false", debug.all("base-config").single().getAttribute("cleartextTrafficPermitted"))
        val cleartext = debug.all("domain-config").single()
        assertEquals("true", cleartext.getAttribute("cleartextTrafficPermitted"))
        assertEquals(listOf("127.0.0.1", "[::1]"), cleartext.all("domain").map { it.textContent.trim() })
        assertEquals(listOf("system"), debug.all("certificates").map { it.getAttribute("src") })
    }
}
