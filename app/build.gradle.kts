import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystorePropertiesFile.inputStream().use { keystoreProperties.load(it) }
}

// Debug-only convenience for local end-to-end tests. Release builds ignore it.
val devGateBase = (findProperty("dravix.devGateBase") as String?)?.trim().orEmpty()

android {
    namespace = "com.dravix.ai"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.dravix.ai"
        minSdk = 24
        // targetSdk stays 28 on purpose: Android 10+ blocks execve() of files
        // in the app data directory for apps targeting 29+, which would break
        // the bundled PRoot/Alpine/OpenCode runtime. This app is sideloaded,
        // not distributed through Play Store.
        targetSdk = 28
        versionCode = 11
        versionName = "2.2.5"

        vectorDrawables {
            useSupportLibrary = true
        }

        // Compiled-in gate URL. There is no runtime override. Debug builds may
        // point at a local mock panel via -Pdravix.devGateBase=...
        buildConfigField(
            "String",
            "GATE_API_BASE",
            "\"https://tool.lightkuro.site\""
        )

        // Comma separated base64 SHA-256 SPKI pins (leaf + intermediate + root).
        // Override at build time with -Pdravix.gatePin="pin1,pin2".
        val gatePin = (findProperty("dravix.gatePin") as String?)
            ?.trim()
            ?: "cmJ/GpwT+B0p8CXGHyUZQzYnjkcCjxPF9nvKB0SyEMs=,kIdp6NNEd8wsugYyyIYFsi1ylMCED3hZbSR8ZFsa/A4=,mEflZT5enoR1FuXLgYYGqnVEoZvmf9c2bVBpiOjYQ0c="
        buildConfigField("String", "GATE_PIN_SHA256", "\"$gatePin\"")

        // Release builds never fall back to plaintext assets.
        buildConfigField("boolean", "ALLOW_PLAIN_ASSETS", "false")
    }

    signingConfigs {
        create("release") {
            if (keystorePropertiesFile.exists()) {
                storeFile = rootProject.file(keystoreProperties["storeFile"] as String)
                storePassword = keystoreProperties["storePassword"] as String
                keyAlias = keystoreProperties["keyAlias"] as String
                keyPassword = keystoreProperties["keyPassword"] as String
            }
        }
    }

    buildTypes {
        debug {
            // Local development only. The release build type below is always
            // false, and AssetVault additionally checks BuildConfig.DEBUG.
            buildConfigField("boolean", "ALLOW_PLAIN_ASSETS", "true")
            val base = devGateBase.ifBlank { "https://tool.lightkuro.site" }
            buildConfigField("String", "GATE_API_BASE", "\"$base\"")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    lint {
        // targetSdk 28 is intentional for the bundled PRoot/OpenCode runtime.
        // This app is distributed directly, not through Play Store.
        checkReleaseBuilds = false
        abortOnError = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }

    androidResources {
        // Plain runtime assets must never be packaged; only their AES-GCM
        // encrypted counterparts (*.enc) are shipped.
        ignoreAssetsPattern = "!.svn:!.git:!.ds_store:!*.scc:.*:<dir>_*:!CVS:!thumbs.db:!picasa.ini:!*~:opencode-aarch64:opencode-x86_64:rootfs-aarch64.bin:rootfs-x86_64.bin"
        noCompress += listOf("gz", "tar", "tgz", "bin", "enc")
    }

    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation("androidx.webkit:webkit:1.11.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.apache.commons:commons-compress:1.26.1")
}

