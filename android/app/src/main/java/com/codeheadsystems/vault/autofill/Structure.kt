package com.codeheadsystems.vault.autofill

/**
 * A view node as the parser needs it: `AssistStructure.ViewNode` through [ViewNodeAdapter] in the
 * app, fakes in the JVM tests. [I] is the autofill ID type.
 */
interface StructNode<I> {
    val autofillId: I?
    val webDomain: String?
    val webScheme: String?
    val autofillHints: List<String>
    val htmlTag: String?
    val htmlAttributes: List<Pair<String, String>>
    val inputType: Int
    val isFocused: Boolean
    val isVisible: Boolean
    val textValue: String?
    val children: List<StructNode<I>>
}

/** What a fillable field is. */
enum class FieldKind { USERNAME, PASSWORD }

/** A fillable field, with the web domain and scheme of its nearest ancestor-or-self that has one. */
data class Field<I>(
    val id: I,
    val kind: FieldKind,
    val webDomain: String?,
    val webScheme: String?,
    val focused: Boolean,
    val value: String?,
)

/** The fields of the focused field's window, and the focused field. */
data class ParsedWindow<I>(val focused: Field<I>, val fields: List<Field<I>>)

/**
 * Structure parsing (docs/android.md, Autofill, step 1): the username and password fields from
 * autofill hints, HTML attributes (Firefox reports an `inputType` of 0), and input types, each with
 * the `webDomain` and `webScheme` of its own node or its nearest ancestor with a non-empty
 * `webDomain`. Firefox sets them on every node of a form; Chrome on a container node; Firefox's root
 * has none or an empty one. Invisible subtrees are skipped.
 */
object Structure {
    // android.text.InputType values, copied so the parser runs on the JVM.
    private const val TYPE_MASK_CLASS = 0x0000000f
    private const val TYPE_MASK_VARIATION = 0x00000ff0
    private const val TYPE_CLASS_TEXT = 0x00000001
    private const val TYPE_CLASS_NUMBER = 0x00000002
    private const val TYPE_TEXT_VARIATION_EMAIL_ADDRESS = 0x00000020
    private const val TYPE_TEXT_VARIATION_PASSWORD = 0x00000080
    private const val TYPE_TEXT_VARIATION_VISIBLE_PASSWORD = 0x00000090
    private const val TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS = 0x000000d0
    private const val TYPE_TEXT_VARIATION_WEB_PASSWORD = 0x000000e0
    private const val TYPE_NUMBER_VARIATION_PASSWORD = 0x00000010

    /**
     * The window that holds the focused field, or null when no fillable field is focused. When
     * several fields claim focus, the deepest wins.
     */
    fun <I> parse(windows: List<StructNode<I>>): ParsedWindow<I>? {
        for (root in windows) {
            val fields = mutableListOf<Pair<Int, Field<I>>>()
            walk(root, null, null, 0, fields)
            val focused = fields.filter { it.second.focused }.maxByOrNull { it.first }?.second ?: continue
            return ParsedWindow(focused, fields.map { it.second })
        }
        return null
    }

    private fun <I> walk(n: StructNode<I>, domain: String?, scheme: String?, depth: Int, out: MutableList<Pair<Int, Field<I>>>) {
        if (!n.isVisible) return
        val own = n.webDomain?.takeIf { it.isNotEmpty() }
        val d = own ?: domain
        val s = if (own != null) n.webScheme?.takeIf { it.isNotEmpty() } else scheme
        val kind = kind(n)
        val id = n.autofillId
        if (kind != null && id != null) out += depth to Field(id, kind, d, s, n.isFocused, n.textValue)
        for (c in n.children) walk(c, d, s, depth + 1, out)
    }

    /** The field kind of a node, or null when it is not a username or password field. */
    fun <I> kind(n: StructNode<I>): FieldKind? {
        val hints = n.autofillHints.map { it.lowercase() }
        val attrs = n.htmlAttributes.associate { it.first.lowercase() to it.second.lowercase() }
        val inputClass = n.inputType and TYPE_MASK_CLASS
        val variation = n.inputType and TYPE_MASK_VARIATION
        val htmlInput = n.htmlTag?.lowercase() == "input"
        val autocomplete = attrs["autocomplete"].orEmpty()
        val password = hints.any { "password" in it } ||
            (htmlInput && attrs["type"] == "password") ||
            "password" in autocomplete ||
            (inputClass == TYPE_CLASS_TEXT && variation in PASSWORD_VARIATIONS) ||
            (inputClass == TYPE_CLASS_NUMBER && variation == TYPE_NUMBER_VARIATION_PASSWORD)
        if (password) return FieldKind.PASSWORD
        val username = hints.any { it == "username" || it == "emailaddress" || it == "email" || "username" in it } ||
            autocomplete == "username" || autocomplete == "email" ||
            (htmlInput && attrs["type"] == "email") ||
            (htmlInput && attrs["type"].orEmpty() in setOf("", "text") && USERNAME_NAMES.any { w ->
                w in attrs["name"].orEmpty() || w in attrs["id"].orEmpty()
            }) ||
            (inputClass == TYPE_CLASS_TEXT && (variation == TYPE_TEXT_VARIATION_EMAIL_ADDRESS || variation == TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS))
        return if (username) FieldKind.USERNAME else null
    }

    /** Words in an HTML input's name or id that mark a username field when nothing else does. */
    private val USERNAME_NAMES = listOf("user", "login", "email")

    private val PASSWORD_VARIATIONS = setOf(
        TYPE_TEXT_VARIATION_PASSWORD,
        TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
        TYPE_TEXT_VARIATION_WEB_PASSWORD,
    )
}
