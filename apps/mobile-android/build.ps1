# Builds the Android app (an APK for 64-bit ARM phones) into target/release/apk.
# Needs: the Android SDK with platform 35 and NDK 28 (sdkmanager "platforms;android-35"
# "ndk;28.2.13676358"), Android Studio's Java (for keytool and apksigner),
#        rustup target add aarch64-linux-android x86_64-linux-android
#        cargo install cargo-apk --locked
# The APK is signed with the Android debug key (~/.android/debug.keystore, made if missing):
# fine for trying it, never for publishing it.
# The activity's Java side (java/, the system's file picker) is compiled with the JDK's javac
# and the SDK's d8, added to the APK cargo-apk made, which is then aligned and signed again.
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
    if ($LASTEXITCODE -ne 0) { throw "cargo apk build failed" }

    $tools = Get-ChildItem "$sdk\build-tools" | Sort-Object Name -Descending | Select-Object -First 1
    $platform = Get-ChildItem "$sdk\platforms" | Sort-Object Name -Descending | Select-Object -First 1
    $androidJar = "$($platform.FullName)\android.jar"
    $work = "target/release/apk/java"
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force "$work/classes", "$work/dex" | Out-Null
    $sources = Get-ChildItem -Recurse "apps/mobile-android/java" -Filter *.java | ForEach-Object { $_.FullName }
    javac --release 11 -cp $androidJar -d "$work/classes" $sources
    if ($LASTEXITCODE -ne 0) { throw "javac failed" }
    $classes = Get-ChildItem -Recurse "$work/classes" -Filter *.class | ForEach-Object { $_.FullName }
    & "$($tools.FullName)\d8.bat" --release --min-api 28 --lib $androidJar --output "$work/dex" $classes
    if ($LASTEXITCODE -ne 0) { throw "d8 failed" }

    $apk = (Resolve-Path "target/release/apk/vault-mobile-android.apk").Path
    Push-Location "$work/dex"
    try {
        & "$($tools.FullName)\aapt.exe" add $apk classes.dex | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "aapt add failed" }
    } finally {
        Pop-Location
    }
    $aligned = "$apk.aligned"
    & "$($tools.FullName)\zipalign.exe" -f -p 4 $apk $aligned
    if ($LASTEXITCODE -ne 0) { throw "zipalign failed" }
    Move-Item -Force $aligned $apk
    & "$($tools.FullName)\apksigner.bat" sign --ks $keystore --ks-pass pass:android `
        --ks-key-alias androiddebugkey --key-pass pass:android $apk
    if ($LASTEXITCODE -ne 0) { throw "apksigner failed" }
    # Only the APK is kept: the unaligned copy and the Java build are left-overs.
    Remove-Item -Recurse -Force $work, "target/release/apk/lib", "target/release/apk/vault-mobile-android-unaligned.apk", "$apk.idsig" -ErrorAction SilentlyContinue
    Write-Host "Built target/release/apk/vault-mobile-android.apk. Install: adb install -r target/release/apk/vault-mobile-android.apk"
} finally {
    Pop-Location
}
