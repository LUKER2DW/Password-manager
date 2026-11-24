# Builds the Android app (an APK for 64-bit ARM phones) into target/release/apk.
# Needs: the Android SDK with platform 35 and NDK 28 (sdkmanager "platforms;android-35"
# "ndk;28.2.13676358"), Android Studio's Java (JDK 17 or newer, for Gradle and keytool),
#        rustup target add aarch64-linux-android x86_64-linux-android
# Two steps: cargo builds the Rust library (the app's screens and everything behind them) with
# the NDK's linker, then Gradle (gradlew, build.gradle) packages it with the Java shell (java/),
# the manifest and res/, and the one library the Java side uses: Google's code scanner. The
# first build fetches Gradle and that library; later builds use Gradle's cache.
# The APK is signed with the Android debug key (~/.android/debug.keystore, made if missing):
# fine for trying it, never for publishing it.
# Speed: the Rust library is built with the `fast` profile (Cargo.toml: optimized, parallel,
# incremental; a rebuild after a change takes a fraction of a full one); -Release uses the
# release profile (one codegen unit, LTO: smaller and a little faster, much slower to build).
# It builds in target/android, apart from the computer's builds, so tests or the desktop app can
# build at the same time.
param([string]$Target = "aarch64-linux-android", [switch]$Release)
$ErrorActionPreference = "Stop"
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA\Android\Sdk" }
$ndk = Get-ChildItem "$sdk\ndk" | Sort-Object Name -Descending | Select-Object -First 1
$bin = "$($ndk.FullName)\toolchains\llvm\prebuilt\windows-x86_64\bin"
if (-not $env:JAVA_HOME) { $env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr" }
$env:Path = "$env:JAVA_HOME\bin;$env:Path"
$env:ANDROID_HOME = $sdk
$env:ANDROID_NDK_ROOT = $ndk.FullName
Remove-Item Env:\ANDROID_SDK_ROOT -ErrorAction SilentlyContinue
foreach ($t in @("aarch64-linux-android", "x86_64-linux-android")) {
    $u = $t.Replace("-", "_")
    Set-Item "Env:CC_$u" "$bin\${t}28-clang.cmd"
    Set-Item "Env:AR_$u" "$bin\llvm-ar.exe"
    Set-Item "Env:CARGO_TARGET_$($u.ToUpper())_LINKER" "$bin\${t}28-clang.cmd"
}
$abi = @{ "aarch64-linux-android" = "arm64-v8a"; "x86_64-linux-android" = "x86_64" }[$Target]
if (-not $abi) { throw "unknown target $Target" }
$keystore = "$HOME\.android\debug.keystore"
if (-not (Test-Path $keystore)) {
    New-Item -ItemType Directory -Force (Split-Path $keystore) | Out-Null
    keytool -genkeypair -keystore $keystore -storepass android -alias androiddebugkey `
        -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
}
Push-Location "$PSScriptRoot/../.."
try {
    $cargoProfile = if ($Release) { "release" } else { "fast" }
    $targetDirBefore = $env:CARGO_TARGET_DIR
    $env:CARGO_TARGET_DIR = "target/android"
    cargo build -p vault-mobile-android --profile $cargoProfile --target $Target
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

    # Where build.gradle takes the native library from (jniLibs), one folder per ABI. The copy
    # loses its symbol table (about a third of the file; the phone never shows a backtrace),
    # which cargo's own output keeps for the next incremental build.
    $libs = "target/android-libs"
    Remove-Item -Recurse -Force $libs -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force "$libs/$abi" | Out-Null
    & "$bin\llvm-strip.exe" --strip-all -o "$libs/$abi/libvault_mobile_android.so" `
        "target/android/$Target/$cargoProfile/libvault_mobile_android.so"
    if ($LASTEXITCODE -ne 0) { throw "llvm-strip failed" }

    Push-Location apps/mobile-android
    try {
        & ./gradlew.bat --quiet assembleRelease
        if ($LASTEXITCODE -ne 0) { throw "gradle failed" }
    } finally {
        Pop-Location
    }

    $out = "target/release/apk"
    New-Item -ItemType Directory -Force $out | Out-Null
    Copy-Item -Force "target/gradle/vault-mobile-android/outputs/apk/release/vault-mobile-android-release.apk" `
        "$out/vault-mobile-android.apk"
    # Left-overs of the builds made with cargo-apk before.
    Remove-Item -Recurse -Force "$out/lib", "$out/manifest", "$out/java", "$out/AndroidManifest.xml", `
        "$out/vault-mobile-android-unaligned.apk" -ErrorAction SilentlyContinue
    Write-Host "Built target/release/apk/vault-mobile-android.apk. Install: adb install -r target/release/apk/vault-mobile-android.apk"
} finally {
    $env:CARGO_TARGET_DIR = $targetDirBefore
    Pop-Location
}
