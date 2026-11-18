plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "dev.getsotto.authenticator"
    compileSdk = 37
    ndkVersion = "27.1.12297006"

    defaultConfig {
        applicationId = "dev.getsotto.authenticator"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0-spike"

        ndk {
            abiFilters += setOf("arm64-v8a", "x86_64")
        }
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.compose.material3:material3")
    implementation("net.java.dev.jna:jna:5.19.1@aar")
}
