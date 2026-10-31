import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

// Release signing activates only when the operator drops a git-ignored
// gen/android/key.properties next to the keystore (see
// packaging/ANDROID_BUILD_RUNBOOK.md). Without it, release builds stay
// unsigned exactly as before - nothing breaks for people who never release.
val keyPropertiesFile = rootProject.file("key.properties")
val keyProperties = Properties().apply {
    if (keyPropertiesFile.exists()) {
        keyPropertiesFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 36
    // The NDK that strips the release .so and extracts its Play debug symbols.
    // Pin a STABLE release (never a beta), installed side by side under
    // $ANDROID_HOME/ndk/<version>, and point NDK_HOME - the NDK the Rust code
    // is compiled and linked with - at the same folder. Bump both together
    // (packaging/ANDROID_BUILD_RUNBOOK.md, "Native library and NDK").
    ndkVersion = "30.0.16248370"
    namespace = "org.example.portty"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "org.example.portty"
        minSdk = 29
        targetSdk = 36
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    signingConfigs {
        create("release") {
            if (keyPropertiesFile.exists()) {
                keyAlias = keyProperties.getProperty("keyAlias")
                keyPassword = keyProperties.getProperty("keyPassword")
                storeFile = file(keyProperties.getProperty("storeFile"))
                storePassword = keyProperties.getProperty("storePassword")
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            // Debug keeps its native symbols through androidComponents below.
            // Never add a packaging {} block here: BuildType has no packaging,
            // so it binds to android.packaging and the RELEASE .so would ship
            // unstripped too (about 10 MB of symbol tables).
        }
        getByName("release") {
            signingConfig =
                if (keyPropertiesFile.exists()) signingConfigs.getByName("release") else null
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
            // The .so ships stripped; its symbol table goes into the AAB
            // instead (BUNDLE-METADATA/com.android.tools.build.debugsymbols),
            // so Play Console can name the functions in native crash reports.
            // FULL would add nothing: release Rust builds carry no DWARF.
            ndk {
                debugSymbolLevel = "SYMBOL_TABLE"
            }
        }
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        buildConfig = true
    }
}

// Only DEBUG builds keep native debug symbols in the .so, so Rust backtraces
// and crash dumps on a test phone show function names. AGP's DSL has no
// per-build-type packaging, hence the variant API.
androidComponents {
    onVariants(selector().withBuildType("debug")) { variant ->
        for (abi in listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")) {
            variant.packaging.jniLibs.keepDebugSymbols.add("*/$abi/*.so")
        }
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    // FCM push doorbell (PorttyMessagingService). Harmless without a Firebase
    // config: FirebaseApp never initializes and the service never runs.
    implementation("com.google.firebase:firebase-messaging:24.1.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

// Firebase/FCM activates only when the operator drops google-services.json
// next to this file (see packaging/PUSH-SETUP.md). Applying the plugin without
// the file would fail EVERY build, including for people who don't want push.
if (file("google-services.json").exists()) {
    apply(plugin = "com.google.gms.google-services")
}

apply(from = "tauri.build.gradle.kts")