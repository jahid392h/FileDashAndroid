plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.filedash.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.filedash.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        ndk { abiFilters += listOf("arm64-v8a") }   // the bundled PHP is arm64 (all modern phones)
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")   // installable APK; use your own keystore for Play Store
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true               // extract libphp.so to nativeLibraryDir so it can be executed
            keepDebugSymbols += "**/libphp.so"      // it is an executable, do not strip it
        }
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
}
