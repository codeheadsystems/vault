package com.codeheadsystems.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** A node for the parser tests. */
data class N(
    override val autofillId: String? = null,
    override val webDomain: String? = null,
    override val webScheme: String? = null,
    override val autofillHints: List<String> = emptyList(),
    override val htmlTag: String? = null,
    override val htmlAttributes: List<Pair<String, String>> = emptyList(),
    override val inputType: Int = 0,
    override val isFocused: Boolean = false,
    override val isVisible: Boolean = true,
    override val textValue: String? = null,
    override val children: List<StructNode<String>> = emptyList(),
) : StructNode<String>

/** Firefox: domain and scheme on every node of a form, an empty domain on the root. */
fun firefoxInput(id: String, host: String, type: String, focused: Boolean = false) = N(
    autofillId = id, webDomain = host, webScheme = "http", htmlTag = "input",
    htmlAttributes = listOf("type" to type, "name" to id), isFocused = focused,
)

fun firefoxForm(host: String, vararg inputs: N) =
    N(autofillId = "form-$host", webDomain = host, webScheme = "http", htmlTag = "form", children = inputs.toList())

class StructureTest {
    @Test
    fun firefoxCrossOriginFramesKeepTheirOwnHosts() {
        // The spike's frame-cross page: the frame's form first (as API 36 lists it), then the top's.
        val root = N(autofillId = "root", webDomain = "", isFocused = true, children = listOf(
            firefoxForm("127.0.0.1", firefoxInput("inuser", "127.0.0.1", "text", focused = true), firefoxInput("inpass", "127.0.0.1", "password")),
            firefoxForm("10.0.2.2", firefoxInput("topuser", "10.0.2.2", "text"), firefoxInput("toppass", "10.0.2.2", "password")),
        ))
        val w = Structure.parse(listOf(root))!!
        assertEquals("inuser", w.focused.id)
        assertEquals("127.0.0.1", w.focused.webDomain)
        assertEquals(listOf("inuser", "inpass", "topuser", "toppass"), w.fields.map { it.id })
        assertEquals(listOf("127.0.0.1", "127.0.0.1", "10.0.2.2", "10.0.2.2"), w.fields.map { it.webDomain })
    }

    @Test
    fun firefoxPasswordFromHtmlTypeWithInputTypeZero() {
        assertEquals(FieldKind.PASSWORD, Structure.kind(firefoxInput("p", "a", "password")))
        assertNull(Structure.kind(firefoxInput("q", "a", "search")))
    }

    @Test
    fun chromeDomainComesFromTheContainer() {
        val container = N(autofillId = "c", webDomain = "10.0.2.2", webScheme = "https", htmlTag = "form", isFocused = true, children = listOf(
            N(autofillId = "u", autofillHints = listOf("username"), htmlTag = "input", isFocused = true),
            N(autofillId = "p", autofillHints = listOf("current-password"), htmlTag = "input"),
        ))
        val w = Structure.parse(listOf(N(children = listOf(container))))!!
        assertEquals("u", w.focused.id)
        assertEquals(listOf("10.0.2.2", "10.0.2.2"), w.fields.map { it.webDomain })
        assertEquals(listOf("https", "https"), w.fields.map { it.webScheme })
        assertEquals(listOf(FieldKind.USERNAME, FieldKind.PASSWORD), w.fields.map { it.kind })
    }

    @Test
    fun appFieldsFromHintsAndInputTypes() {
        val textPassword = 0x00000001 or 0x00000080
        val email = 0x00000001 or 0x00000020
        val root = N(children = listOf(
            N(autofillId = "e", inputType = email, isFocused = true),
            N(autofillId = "p", inputType = textPassword),
            N(autofillId = "x", inputType = 0x00000001),
        ))
        val w = Structure.parse(listOf(root))!!
        assertEquals(listOf("e" to FieldKind.USERNAME, "p" to FieldKind.PASSWORD), w.fields.map { it.id to it.kind })
        assertNull(w.focused.webDomain)
    }

    @Test
    fun invisibleSubtreesAreSkipped() {
        val root = N(children = listOf(
            N(autofillId = "u", autofillHints = listOf("username"), isFocused = true),
            N(isVisible = false, children = listOf(N(autofillId = "hidden", autofillHints = listOf("password")))),
        ))
        assertEquals(listOf("u"), Structure.parse(listOf(root))!!.fields.map { it.id })
    }

    @Test
    fun onlyTheFocusedWindowCounts() {
        val other = N(children = listOf(N(autofillId = "o", autofillHints = listOf("password"))))
        val focused = N(children = listOf(N(autofillId = "f", autofillHints = listOf("password"), isFocused = true)))
        assertEquals(listOf("f"), Structure.parse(listOf(other, focused))!!.fields.map { it.id })
    }

    @Test
    fun noFocusedFieldGivesNothing() {
        val root = N(isFocused = true, children = listOf(N(autofillId = "u", autofillHints = listOf("username"))))
        assertNull(Structure.parse(listOf(root)))
    }

    @Test
    fun emptyDomainIsNoDomain() {
        val root = N(webDomain = "", webScheme = null, children = listOf(N(autofillId = "u", autofillHints = listOf("username"), isFocused = true)))
        val f = Structure.parse(listOf(root))!!.focused
        assertNull(f.webDomain)
        assertNull(f.webScheme)
    }
}
