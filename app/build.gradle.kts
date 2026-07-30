plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "org.witaqua.pwn.device"
    compileSdk = 37
    // Pinned rather than left to AGP's default so a checkout and CI compile the
    // native probe with the same toolchain. This is what AGP 9.2.1 selects on
    // its own today; CI installs exactly it.
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "org.witaqua.pwn.device"
        minSdk = 33
        targetSdk = 36
        versionCode = 11
        versionName = "0.0.4"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += "arm64-v8a"
        }

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=none"
            }
        }
    }

    signingConfigs {
        // app/android.jks is the publicly known AOSP debug key (CN=Android,
        // alias and every password "android"). It is committed on purpose so
        // that debug builds from CI and from a checkout carry the same
        // signature and install over each other.
        //
        // It is NOT a release key and must never become one: the private key is
        // public, so anyone could sign an update over an app signed with it.
        create("android") {
            storeFile = file("android.jks")
            storePassword = "android"
            keyAlias = "android"
            keyPassword = "android"
        }
        // Real releases are signed with a key that is not in the repository.
        // CI writes app/release.jks from the STORE_FILE secret; the config only
        // exists when that file does, so an unsigned-release build is a plain
        // unsigned APK rather than a build failure.
        if (file("release.jks").exists()) {
            create("release") {
                storeFile = file("release.jks")
                storePassword = System.getenv("STORE_PASSWORD")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        getByName("debug") {
            signingConfig = signingConfigs.getByName("android")
        }
        getByName("release") {
            if (file("release.jks").exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    packaging {
        // Required, not a preference: the APK ships libcve43499root.so, which
        // is an executable rather than a library. InstallViewModel runs it with
        // ProcessBuilder out of nativeLibraryDir, and only legacy packaging
        // extracts it there as a real file. Uncompressed-and-mapped leaves
        // nothing to exec.
        jniLibs.useLegacyPackaging = true
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3ExpressiveApi",
        )
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.05.01"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3:1.5.0-alpha24")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("com.materialkolor:material-kolor:4.1.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:core-ktx:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
}
