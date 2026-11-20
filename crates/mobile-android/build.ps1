# Builds the Android app (an APK for 64-bit ARM phones) into target/release/apk.
# Needs: the Android SDK with platform 35 and NDK 28 (sdkmanager "platforms;android-35"
# "ndk;28.2.13676358"), Android Studio's Java (for keytool and apksigner),
#        rustup target add aarch64-linux-android x86_64-linux-android
#        cargo install cargo-apk --locked
# The APK is signed with the Android debug key (~/.android/debug.keystore, made if missing):
# fine for trying it, never for publishing it.
param([string]$Target = "aarch64-linux-android")
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
$keystore = "$HOME\.android\debug.keystore"
if (-not (Test-Path $keystore)) {
    New-Item -ItemType Directory -Force (Split-Path $keystore) | Out-Null
    keytool -genkeypair -keystore $keystore -storepass android -alias androiddebugkey `
        -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
}
$env:CARGO_APK_RELEASE_KEYSTORE = $keystore
$env:CARGO_APK_RELEASE_KEYSTORE_PASSWORD = "android"
Push-Location "$PSScriptRoot/../.."
try {
    cargo apk build -p vault-mobile-android --release --target $Target
    Write-Host "Built target/release/apk/vault-mobile-android.apk. Install: adb install -r target/release/apk/vault-mobile-android.apk"
} finally {
    Pop-Location
}
