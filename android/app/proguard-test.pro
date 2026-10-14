# Only for the release gate (-Pvault.testBuildType=release): the test APK takes these shared
# libraries from the app under test, so R8 must keep them. The shipped release does not use this.
-keep class androidx.tracing.** { *; }
-keep class kotlin.** { *; }
-keep class androidx.test.** { *; }
