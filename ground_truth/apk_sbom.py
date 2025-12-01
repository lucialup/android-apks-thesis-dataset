#!/usr/bin/env python3
"""
APK SBOM Generator
Makes a single SBOM file per APK with:
- App metadata name, package, version, permissions
- Third-party libraries (from DEX class)
- Trackers (from known signatures)
- AndroidX dependencies (from META-INF)
"""

import json
import sys
import os
import re
import logging
import zipfile
from datetime import datetime
from typing import Dict, List, Set, Optional

logging.getLogger("androguard").setLevel(logging.ERROR)

LIBRARY_SIGNATURES = {
    # Cross platform frameworks
    "io.flutter": {"name": "Flutter", "category": "framework"},
    "com.facebook.react": {"name": "React Native", "category": "framework"},
    "com.unity3d": {"name": "Unity", "category": "framework"},
    "org.libsdl": {"name": "SDL", "category": "framework"},
    "org.qtproject": {"name": "Qt", "category": "framework"},
    "org.kivy": {"name": "Kivy", "category": "framework"},
    "com.xamarin": {"name": "Xamarin", "category": "framework"},
    "mono.android": {"name": "Xamarin/Mono", "category": "framework"},

    # Networking
    "okhttp3": {"name": "OkHttp", "category": "networking"},
    "okio": {"name": "Okio", "category": "networking"},
    "retrofit2": {"name": "Retrofit2", "category": "networking"},
    "com.squareup.okhttp3": {"name": "OkHttp", "category": "networking"},
    "com.squareup.okhttp": {"name": "OkHttp2", "category": "networking"},
    "com.squareup.retrofit2": {"name": "Retrofit2", "category": "networking"},
    "io.ktor": {"name": "Ktor", "category": "networking"},
    "com.android.volley": {"name": "Volley", "category": "networking"},
    "com.loopj.android": {"name": "AsyncHttpClient", "category": "networking"},

    # JSON
    "com.google.gson": {"name": "Gson", "category": "serialization"},
    "com.squareup.moshi": {"name": "Moshi", "category": "serialization"},
    "kotlinx.serialization": {"name": "Kotlinx Serialization", "category": "serialization"},
    "com.fasterxml.jackson": {"name": "Jackson", "category": "serialization"},
    "com.google.protobuf": {"name": "Protocol Buffers", "category": "serialization"},
    "com.google.flatbuffers": {"name": "FlatBuffers", "category": "serialization"},

    # Image loading
    "com.bumptech.glide": {"name": "Glide", "category": "image"},
    "com.github.bumptech.glide": {"name": "Glide", "category": "image"},
    "com.squareup.picasso": {"name": "Picasso", "category": "image"},
    "coil": {"name": "Coil", "category": "image"},
    "io.coil": {"name": "Coil", "category": "image"},
    "com.facebook.fresco": {"name": "Fresco", "category": "image"},
    "com.nostra13.universalimageloader": {"name": "Universal Image Loader", "category": "image"},

    # Media playback
    "com.google.android.exoplayer": {"name": "ExoPlayer", "category": "media"},
    "com.google.android.exoplayer2": {"name": "ExoPlayer2", "category": "media"},
    "androidx.media3.exoplayer": {"name": "Media3 ExoPlayer", "category": "media"},
    "androidx.media3": {"name": "Media3", "category": "media"},
    "tv.danmaku.ijk": {"name": "IjkPlayer", "category": "media"},
    "com.devbrackets.android.exomedia": {"name": "ExoMedia", "category": "media"},

    # Dependency injection
    "dagger": {"name": "Dagger", "category": "di"},
    "com.google.dagger": {"name": "Dagger/Hilt", "category": "di"},
    "dagger.hilt": {"name": "Hilt", "category": "di"},
    "org.koin": {"name": "Koin", "category": "di"},
    "javax.inject": {"name": "JSR-330 Inject", "category": "di"},
    "toothpick": {"name": "Toothpick", "category": "di"},

    # Reactive abnd Async
    "io.reactivex.rxjava3": {"name": "RxJava3", "category": "reactive"},
    "io.reactivex.rxjava2": {"name": "RxJava2", "category": "reactive"},
    "io.reactivex": {"name": "RxJava", "category": "reactive"},
    "kotlinx.coroutines": {"name": "Kotlin Coroutines", "category": "reactive"},
    "org.reactivestreams": {"name": "Reactive Streams", "category": "reactive"},

    # Database
    "io.realm": {"name": "Realm", "category": "database"},
    "net.sqlcipher": {"name": "SQLCipher", "category": "database"},
    "app.cash.sqldelight": {"name": "SQLDelight", "category": "database"},
    "androidx.room": {"name": "Room", "category": "database"},
    "io.objectbox": {"name": "ObjectBox", "category": "database"},
    "org.greenrobot.greendao": {"name": "GreenDAO", "category": "database"},
    "androidx.datastore": {"name": "DataStore", "category": "storage"},

    # Google services
    "com.google.firebase": {"name": "Firebase", "category": "firebase"},
    "com.google.firebase.auth": {"name": "Firebase Auth", "category": "firebase"},
    "com.google.firebase.database": {"name": "Firebase Realtime DB", "category": "firebase"},
    "com.google.firebase.firestore": {"name": "Firebase Firestore", "category": "firebase"},
    "com.google.firebase.messaging": {"name": "Firebase Cloud Messaging", "category": "firebase"},
    "com.google.firebase.storage": {"name": "Firebase Storage", "category": "firebase"},
    "com.google.android.gms": {"name": "Google Play Services", "category": "google"},
    "com.google.mlkit": {"name": "ML Kit", "category": "ml"},
    "com.google.android.play": {"name": "Google Play Core", "category": "google"},

    # Architecture comp
    "androidx.navigation": {"name": "Navigation", "category": "jetpack"},
    "androidx.work": {"name": "WorkManager", "category": "jetpack"},
    "androidx.paging": {"name": "Paging", "category": "jetpack"},
    "androidx.lifecycle": {"name": "Lifecycle", "category": "jetpack"},
    "androidx.hilt": {"name": "Hilt", "category": "jetpack"},
    "androidx.camera": {"name": "CameraX", "category": "jetpack"},
    "androidx.biometric": {"name": "Biometric", "category": "jetpack"},

    # Crypto
    "org.bouncycastle": {"name": "Bouncy Castle", "category": "crypto"},
    "org.conscrypt": {"name": "Conscrypt", "category": "crypto"},
    "com.google.crypto.tink": {"name": "Tink", "category": "crypto"},
    "net.zetetic": {"name": "SQLCipher", "category": "crypto"},

    # UI
    "com.airbnb.lottie": {"name": "Lottie", "category": "ui"},
    "com.google.android.material": {"name": "Material Components", "category": "ui"},
    "androidx.compose": {"name": "Jetpack Compose", "category": "ui"},
    "com.github.PhilJay": {"name": "MPAndroidChart", "category": "ui"},

    # Logging
    "timber.log": {"name": "Timber", "category": "logging"},
    "org.slf4j": {"name": "SLF4J", "category": "logging"},
    "ch.qos.logback": {"name": "Logback", "category": "logging"},
    "com.orhanobut.logger": {"name": "Logger", "category": "logging"},

    # Utility
    "com.jakewharton": {"name": "JakeWharton Utils", "category": "utility"},
    "org.apache.commons": {"name": "Apache Commons", "category": "utility"},
    "org.jsoup": {"name": "Jsoup", "category": "html"},
    "com.google.zxing": {"name": "ZXing", "category": "barcode"},
    "com.journeyapps.barcodescanner": {"name": "ZXing Android", "category": "barcode"},
    "org.greenrobot.eventbus": {"name": "EventBus", "category": "utility"},
}

NATIVE_LIB_SIGNATURES = {
    "libflutter.so": {"name": "Flutter", "category": "framework"},
    "libreactnativejni.so": {"name": "React Native", "category": "framework"},
    "libjsc.so": {"name": "React Native (JSC)", "category": "framework"},
    "libhermes.so": {"name": "React Native (Hermes)", "category": "framework"},
    "libunity.so": {"name": "Unity", "category": "framework"},
    "libmain.so": {"name": "Unity", "category": "framework"},
    "libSDL2.so": {"name": "SDL2", "category": "framework"},
    "libQt5Core.so": {"name": "Qt", "category": "framework"},
    "libgodot_android.so": {"name": "Godot", "category": "framework"},
    "libimagepipeline.so": {"name": "Fresco", "category": "image"},
    "libnative-imagetranscoder.so": {"name": "Fresco", "category": "image"},
    "libimage_processing_util_jni.so": {"name": "CameraX/ML Kit", "category": "image"},
    "libdatastore_shared_counter.so": {"name": "DataStore", "category": "storage"},
    "libsqlcipher.so": {"name": "SQLCipher", "category": "database"},
    "librealm-jni.so": {"name": "Realm", "category": "database"},
    "libconscrypt_jni.so": {"name": "Conscrypt", "category": "crypto"},
    "libffmpeg.so": {"name": "FFmpeg", "category": "media"},
    "libavcodec.so": {"name": "FFmpeg", "category": "media"},
    "libijkffmpeg.so": {"name": "IjkPlayer", "category": "media"},
    "libexoplayer.so": {"name": "ExoPlayer", "category": "media"},
    "libweblayer.so": {"name": "WebView", "category": "webview"},
    "libchromium.so": {"name": "Chromium WebView", "category": "webview"},
}

TRACKER_SIGNATURES = {
    "com.google.firebase.analytics": {"name": "Firebase Analytics", "category": "analytics"},
    "com.google.android.gms.analytics": {"name": "Google Analytics", "category": "analytics"},
    "com.facebook.appevents": {"name": "Facebook Analytics", "category": "analytics"},
    "com.amplitude": {"name": "Amplitude", "category": "analytics"},
    "com.mixpanel": {"name": "Mixpanel", "category": "analytics"},
    "io.sentry": {"name": "Sentry", "category": "crash_reporting"},
    "com.crashlytics": {"name": "Crashlytics", "category": "crash_reporting"},
    "com.google.firebase.crashlytics": {"name": "Firebase Crashlytics", "category": "crash_reporting"},
    "com.google.android.gms.ads": {"name": "Google Ads", "category": "advertising"},
    "com.facebook.ads": {"name": "Facebook Ads", "category": "advertising"},
    "com.unity3d.ads": {"name": "Unity Ads", "category": "advertising"},
    "com.appsflyer": {"name": "AppsFlyer", "category": "attribution"},
    "com.adjust.sdk": {"name": "Adjust", "category": "attribution"},
}


def extract_native_libs(apk_path: str) -> Set[str]:
    native_libs = set()
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.so') and '/lib/' in name:
                    lib_name = os.path.basename(name)
                    native_libs.add(lib_name)
    except Exception:
        pass
    return native_libs


def extract_androidx_versions(apk_path: str) -> Dict[str, str]:
    versions = {}
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for name in zf.namelist():
                if name.startswith("META-INF/") and name.endswith(".version"):
                    lib_name = name[9:-8]
                    lib_name = lib_name.replace("_", "/")

                    version = zf.read(name).decode('utf-8').strip()
                    versions[lib_name] = version
    except Exception:
        pass
    return versions


def analyze_apk(apk_path: str) -> dict:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX

    result = {
        "sbom_version": "1.0",
        "generated_at": datetime.now().isoformat(),
        "tool": "apk_sbom.py",
        "apk": {},
        "app": {},
        "permissions": [],
        "libraries": [],
        "trackers": [],
        "stats": {}
    }

    try:
        apk = APK(apk_path)

        result["apk"] = {
            "path": os.path.basename(apk_path),
            "size_bytes": os.path.getsize(apk_path),
        }

        result["app"] = {
            "package": apk.get_package(),
            "name": apk.get_app_name(),
            "version_name": apk.get_androidversion_name(),
            "version_code": apk.get_androidversion_code(),
            "min_sdk": apk.get_min_sdk_version(),
            "target_sdk": apk.get_target_sdk_version(),
        }

        result["permissions"] = sorted(apk.get_permissions())

        androidx_versions = extract_androidx_versions(apk_path)

        native_libs = extract_native_libs(apk_path)

        all_classes: Set[str] = set()
        for dex_name in apk.get_dex_names():
            dex_data = apk.get_file(dex_name)
            if dex_data:
                dex = DEX(dex_data)
                for class_def in dex.get_classes():
                    class_name = class_def.get_name()
                    if class_name.startswith('L') and class_name.endswith(';'):
                        class_name = class_name[1:-1].replace('/', '.')
                    all_classes.add(class_name)

        detected_libs = {}
        for class_name in all_classes:
            for signature, lib_info in LIBRARY_SIGNATURES.items():
                if class_name.startswith(signature):
                    lib_name = lib_info["name"]
                    if lib_name not in detected_libs:
                        detected_libs[lib_name] = {
                            "name": lib_name,
                            "category": lib_info["category"],
                            "package": signature,
                        }
                    break

        detected_trackers = {}
        for class_name in all_classes:
            for signature, tracker_info in TRACKER_SIGNATURES.items():
                if class_name.startswith(signature):
                    tracker_name = tracker_info["name"]
                    if tracker_name not in detected_trackers:
                        detected_trackers[tracker_name] = {
                            "name": tracker_name,
                            "category": tracker_info["category"],
                            "package": signature,
                        }
                    break

        for lib_file in native_libs:
            if lib_file in NATIVE_LIB_SIGNATURES:
                lib_info = NATIVE_LIB_SIGNATURES[lib_file]
                lib_name = lib_info["name"]
                if lib_name not in detected_libs:
                    detected_libs[lib_name] = {
                        "name": lib_name,
                        "category": lib_info["category"],
                        "native_lib": lib_file,
                    }

        for lib_name, version in androidx_versions.items():
            if "annotation" in lib_name.lower() and "experimental" in lib_name.lower():
                continue
            detected_libs[lib_name] = {
                "name": lib_name,
                "version": version,
                "category": "androidx",
                "package": lib_name.replace("/", "."),
            }

        result["libraries"] = sorted(detected_libs.values(), key=lambda x: x["name"])
        result["trackers"] = sorted(detected_trackers.values(), key=lambda x: x["name"])

        result["stats"] = {
            "total_classes": len(all_classes),
            "total_libraries": len(result["libraries"]),
            "total_trackers": len(result["trackers"]),
            "total_permissions": len(result["permissions"]),
        }

    except Exception as e:
        result["error"] = str(e)

    return result


def main():
    if len(sys.argv) < 2:
        print("Usage: apk_sbom.py <apk_path> [output.json]", file=sys.stderr)
        print("       apk_sbom.py --batch <apk_dir> <output_dir>", file=sys.stderr)
        sys.exit(1)

    if sys.argv[1] == "--batch":
        if len(sys.argv) < 4:
            print("Usage: apk_sbom.py --batch <apk_dir> <output_dir>", file=sys.stderr)
            sys.exit(1)

        apk_dir = sys.argv[2]
        output_dir = sys.argv[3]
        os.makedirs(output_dir, exist_ok=True)

        apk_files = [f for f in os.listdir(apk_dir) if f.endswith('.apk')]
        for i, apk_file in enumerate(sorted(apk_files), 1):
            apk_path = os.path.join(apk_dir, apk_file)
            output_name = apk_file.rsplit('_', 1)[0] + '.sbom.json'
            output_path = os.path.join(output_dir, output_name)

            print(f"[{i}/{len(apk_files)}] {apk_file}", file=sys.stderr)

            sbom = analyze_apk(apk_path)
            with open(output_path, 'w') as f:
                json.dump(sbom, f, indent=2)
    else:
        apk_path = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else None

        print(f"Analyzing: {apk_path}", file=sys.stderr)
        sbom = analyze_apk(apk_path)

        output = json.dumps(sbom, indent=2)
        if output_path:
            with open(output_path, 'w') as f:
                f.write(output)
            print(f"Saved to: {output_path}", file=sys.stderr)
        else:
            print(output)


if __name__ == "__main__":
    main()
