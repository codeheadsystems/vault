import groovy.xml.XmlSlurper
import groovy.xml.slurpersupport.GPathResult
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// The repository root, which holds the Cargo workspace and deny.toml.
val repoRoot: File = rootDir.parentFile

// The Cargo profile the shipped library is built with (Cargo.toml, profile.android). The host build
// for the JVM tests uses it too, so the tests run the same code the app ships.
val cargoProfile = "android"

// The build type the instrumented tests run against: debug by default; release for the release
// gate, which runs against the library inside the release APK.
val testBuildTypeName = providers.gradleProperty("vault.testBuildType").getOrElse("debug")

android {
    namespace = "com.codeheadsystems.vault"
    // Compose 1.12 needs API 37 to compile against; the app still targets 36.
    compileSdk = 37

    defaultConfig {
        applicationId = "com.codeheadsystems.vault"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        // JNA ships seven ABIs; the app ships the two the native library is built for.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    testBuildType = testBuildTypeName

    // A release build is signed only when the owner's key is configured (docs/android.md,
    // Distribution); otherwise it is left unsigned, as CI builds it.
    val storeFile = providers.gradleProperty("vault.signing.storeFile").orNull
    if (storeFile != null) {
        signingConfigs.create("release") {
            this.storeFile = file(storeFile)
            storePassword = providers.gradleProperty("vault.signing.storePassword").get()
            keyAlias = providers.gradleProperty("vault.signing.keyAlias").get()
            keyPassword = providers.gradleProperty("vault.signing.keyPassword").get()
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (storeFile != null) {
                signingConfig = signingConfigs.getByName("release")
            } else if (testBuildTypeName == "release") {
                // The release gate installs the release APK, which then needs some signature.
                signingConfig = signingConfigs.getByName("debug")
            }
            if (testBuildTypeName == "release") proguardFiles("proguard-test.pro")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        // The in-memory host and state builder both test source sets use.
        getByName("test").kotlin.srcDir("src/sharedTest/java")
        getByName("androidTest").kotlin.srcDir("src/sharedTest/java")
        getByName("androidTest").assets.srcDir(File(repoRoot, "spec/vectors"))
    }

    lint {
        error += "NewApi"
        abortOnError = true
        checkReleaseBuilds = true
    }

    testOptions {
        unitTests.all {
            // ManifestTest reads the merged manifest of the variant under test.
            it.systemProperty("vault.mergedManifests", layout.buildDirectory.dir("intermediates").get().asFile.path)
            it.systemProperty("vault.sourceManifest", file("src/main/AndroidManifest.xml").path)
            // The generated bindings load the host build of vault-android through desktop JNA.
            it.systemProperty("jna.library.path", File(repoRoot, "target/$cargoProfile").path)
            it.systemProperty("vault.vectors", File(repoRoot, "spec/vectors").path)
        }
    }

}

// JNA's desktop jar, with the host's native dispatch library, for the JVM tests; the app ships the
// Android aar.
val jnaDesktop: Configuration by configurations.creating

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.process)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.zxing.core)
    implementation(libs.coroutines.android)
    implementation(variantOf(libs.jna) { artifactType("aar") })

    testImplementation(libs.junit)
    androidTestImplementation(libs.junit)
    androidTestImplementation(libs.test.runner)
    androidTestImplementation(libs.test.rules)
    androidTestImplementation(libs.test.core)
    androidTestImplementation(libs.test.ext.junit)
    androidTestImplementation(libs.uiautomator)
    testImplementation(libs.json)
    jnaDesktop(libs.jna)
    // JNA finds its native dispatch library as a classpath resource, which the aar lacks.
    testRuntimeOnly(files(jnaDesktop))
}

// ManifestTest reads the merged manifest of both variants; the binding tests load the host library.
tasks.withType<Test>().configureEach {
    dependsOn("processDebugMainManifest", "processReleaseMainManifest", cargoHost)
}

// Native library and bindings (docs/android.md, Build and tests): plain Exec tasks, no plugin,
// registered per variant through the variant API, which assigns each its output directory. Cargo
// decides what to rebuild, so the tasks always run; unchanged outputs leave the build up to date.

/** `cargo ndk`, writing the libraries for arm64-v8a and x86_64 into [outputDir]. */
abstract class CargoNdk : Exec() {
    @get:OutputDirectory abstract val outputDir: DirectoryProperty
}

/** `uniffi-bindgen`, writing the Kotlin bindings into [outputDir]. */
abstract class UniffiBindgen : Exec() {
    @get:OutputDirectory abstract val outputDir: DirectoryProperty
}

val cargoHost by tasks.registering(Exec::class) {
    description = "Builds crates/vault-android for the host, for the JVM tests."
    workingDir = repoRoot
    commandLine("cargo", "build", "-q", "--locked", "-p", "vault-android", "--profile", cargoProfile)
    outputs.upToDateWhen { false }
}

// The android profile strips the library, and with it the UniFFI metadata uniffi-bindgen reads,
// so the bindings come from an unstripped host build of the same source.
val cargoMetadata by tasks.registering(Exec::class) {
    description = "Builds crates/vault-android unstripped for the host, for uniffi-bindgen."
    workingDir = repoRoot
    commandLine("cargo", "build", "-q", "--locked", "-p", "vault-android")
    outputs.upToDateWhen { false }
}

androidComponents.onVariants { variant ->
    val name = variant.name.replaceFirstChar { it.uppercase() }
    val ndk = tasks.register<CargoNdk>("cargoNdk$name") {
        description = "Builds crates/vault-android for arm64-v8a and x86_64 with cargo ndk."
        workingDir = repoRoot
        executable = "cargo"
        argumentProviders.add(CommandLineArgumentProvider {
            listOf(
                "ndk", "-t", "arm64-v8a", "-t", "x86_64", "-P", "29", "-o", outputDir.get().asFile.path,
                "build", "-q", "--locked", "-p", "vault-android", "--profile", cargoProfile,
            )
        })
        outputs.upToDateWhen { false }
    }
    val bindgen = tasks.register<UniffiBindgen>("uniffiBindgen$name") {
        description = "Generates the Kotlin bindings of crates/vault-android with uniffi-bindgen."
        dependsOn(ndk, cargoMetadata)
        workingDir = repoRoot
        executable = "cargo"
        argumentProviders.add(CommandLineArgumentProvider {
            listOf(
                "run", "-q", "--locked", "-p", "vault-android", "--features", "bindgen", "--bin", "uniffi-bindgen", "--",
                "generate", "--library", File(repoRoot, "target/debug/libvault_android.so").path,
                "--language", "kotlin", "--no-format", "--out-dir", outputDir.get().asFile.path,
            )
        })
        outputs.upToDateWhen { false }
    }
    variant.sources.jniLibs?.addGeneratedSourceDirectory(ndk, CargoNdk::outputDir)
    variant.sources.java?.addGeneratedSourceDirectory(bindgen, UniffiBindgen::outputDir)
}

// Licence check (docs/android.md, Dependencies): every runtime artefact of the release build must
// carry licences that deny.toml allows, read from deny.toml as extension/licences.mjs does.
//
// A POM that lists several licences is read as all of them (AND). An artefact offered under a
// choice of licences is named here with its SPDX expression; the check still requires the POM to
// declare exactly the licences the expression names, so a licence change fails the check.
val dualLicensed = mapOf(
    "net.java.dev.jna:jna" to "LGPL-2.1-or-later OR Apache-2.0",
)

// POM licence names and URLs, mapped to SPDX identifiers. An unknown name fails the check.
val spdxByName = mapOf(
    "apache-2.0" to "Apache-2.0",
    "apache 2.0" to "Apache-2.0",
    "apache license 2.0" to "Apache-2.0",
    "apache license, version 2.0" to "Apache-2.0",
    "the apache license, version 2.0" to "Apache-2.0",
    "the apache software license, version 2.0" to "Apache-2.0",
    "bsd-3-clause" to "BSD-3-Clause",
    "the 3-clause bsd license" to "BSD-3-Clause",
    "mit" to "MIT",
    "the mit license" to "MIT",
    "mit license" to "MIT",
    "lgpl-2.1-or-later" to "LGPL-2.1-or-later",
    "mozilla public license 2.0" to "MPL-2.0",
    "mpl-2.0" to "MPL-2.0",
)
val spdxByUrl = mapOf(
    "apache.org/licenses/license-2.0" to "Apache-2.0",
    "opensource.org/licenses/mit" to "MIT",
)

val checkLicences by tasks.registering {
    description = "Holds every release runtime artefact to the licences deny.toml allows."
    group = "verification"
    val denyToml = File(repoRoot, "deny.toml")
    inputs.file(denyToml)
    doLast {
        val deny = denyToml.readText()
        val block = Regex("""\[licenses\][\s\S]*?\nallow = \[([\s\S]*?)\]""").find(deny)
            ?: throw GradleException("deny.toml: no [licenses] allow list")
        val allowed = Regex("\"([^\"]+)\"").findAll(block.groupValues[1]).map { it.groupValues[1] }.toSet()

        val modules = configurations.getByName("releaseRuntimeClasspath").incoming.resolutionResult.allComponents
            .mapNotNull { it.id as? ModuleComponentIdentifier }
        val failures = mutableListOf<String>()
        for (m in modules.sortedBy { it.displayName }) {
            val coordinates = "${m.group}:${m.module}"
            val declared = try {
                pomLicences(m.group, m.module, m.version)
            } catch (e: Exception) {
                failures += "${m.displayName}: ${e.message}"
                continue
            }
            val expression = dualLicensed[coordinates]
            if (expression != null) {
                val named = expression.split(" OR ", " AND ").map { it.trim() }.toSet()
                if (declared.toSet() != named) {
                    failures += "${m.displayName}: POM declares $declared, but the build reads it as $expression"
                } else if (!satisfiable(expression, allowed)) {
                    failures += "${m.displayName}: $expression"
                }
            } else if (declared.isEmpty()) {
                failures += "${m.displayName}: no licence"
            } else if (!declared.all { it in allowed }) {
                failures += "${m.displayName}: ${declared.joinToString(" AND ")}"
            }
        }
        if (failures.isNotEmpty()) {
            throw GradleException(
                "licences: ${failures.size} artefact(s) with a licence deny.toml does not allow:\n  " +
                    failures.joinToString("\n  "),
            )
        }
        logger.lifecycle("licences: ${modules.size} artefacts, all allowed")
    }
}

/** The SPDX identifiers of a POM's licences, following parent POMs when it declares none. */
fun pomLicences(group: String, module: String, version: String, depth: Int = 0): List<String> {
    val pom = configurations.detachedConfiguration(dependencies.create("$group:$module:$version@pom"))
        .apply { isTransitive = false }.singleFile
    val xml: GPathResult = XmlSlurper(false, false).parse(pom)
    val licences = (xml.getProperty("licenses") as GPathResult).getProperty("license") as GPathResult
    val found = licences.map { node ->
        val l = node as GPathResult
        val name = (l.getProperty("name") as GPathResult).text().trim()
        val url = (l.getProperty("url") as GPathResult).text().trim().lowercase()
            .removePrefix("https://").removePrefix("http://").removePrefix("www.").removeSuffix(".txt").removeSuffix("/")
        spdxByName[name.lowercase()] ?: spdxByUrl[url]
            ?: throw GradleException("unknown licence name \"$name\" ($url)")
    }
    if (found.isNotEmpty()) return found.distinct()
    val parent = xml.getProperty("parent") as GPathResult
    if (parent.isEmpty || depth >= 5) return emptyList()
    return pomLicences(
        (parent.getProperty("groupId") as GPathResult).text().trim(),
        (parent.getProperty("artifactId") as GPathResult).text().trim(),
        (parent.getProperty("version") as GPathResult).text().trim(),
        depth + 1,
    )
}

/** Whether an SPDX expression is satisfiable from the allowed licences: OR needs one side, AND both. */
fun satisfiable(expression: String, allowed: Set<String>): Boolean =
    expression.split(" OR ").any { alternative -> alternative.split(" AND ").all { it.trim() in allowed } }

tasks.named("check") { dependsOn(checkLicences) }
