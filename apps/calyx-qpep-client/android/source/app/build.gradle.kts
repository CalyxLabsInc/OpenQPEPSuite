plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.calyxlabs.qpepclient"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.calyxlabs.qpepclient"
        minSdk = 29
        targetSdk = 37
        versionCode = 219
        versionName = "PC 1.0.0"
    }
}
