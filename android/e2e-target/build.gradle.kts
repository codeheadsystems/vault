// A login form that the instrumented tests fill through the autofill framework, as the requesting
// app (docs/android.md, Build and tests). It is never shipped.
plugins { alias(libs.plugins.android.application) }

android {
    namespace = "com.codeheadsystems.vault.e2etarget"
    compileSdk = 37
    defaultConfig {
        applicationId = "com.codeheadsystems.vault.e2etarget"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
