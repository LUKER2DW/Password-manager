# Checks the manifest of a built APK: the one Android reads, after Gradle merged in the
# libraries' own. The protections the app's manifest sets are in it (no backup and no copy to a
# new phone, no task affinity, other apps' overlays hidden, Android 12 at least, no plain http),
# it asks for no permission but those listed here, and no part of it is open to other apps but
# the launcher screen and the two services only Android may bind to. A library that adds a
# permission or an exported component on its next version stops the build here, until that is
# looked at and written down below.
#   check-manifest.ps1 -Apk <apk> [-Sdk <Android SDK folder>]
# Run by build.ps1 and .github/workflows/release.yml; pwsh on Linux too.
param(
    [Parameter(Mandatory)] [string]$Apk,
    [string]$Sdk = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA\Android\Sdk" }),
    [int]$MinSdk = 31
)
$ErrorActionPreference = "Stop"
$ext = if ($IsLinux -or $IsMacOS) { "" } else { ".bat" }
$tool = Join-Path $Sdk "cmdline-tools/latest/bin/apkanalyzer$ext"
if (-not (Test-Path $tool)) { throw "apkanalyzer is missing: sdkmanager `"cmdline-tools;latest`"" }
$text = & $tool manifest print $Apk
if ($LASTEXITCODE -ne 0) { throw "apkanalyzer failed on $Apk" }
[xml]$manifest = $text -join "`n"
$android = "http://schemas.android.com/apk/res/android"
$problems = @()

$root = $manifest.DocumentElement
$usesSdk = $root.SelectSingleNode("uses-sdk")
if ($usesSdk.GetAttribute("minSdkVersion", $android) -ne "$MinSdk") {
    $problems += "minSdkVersion is $($usesSdk.GetAttribute("minSdkVersion", $android)), not $MinSdk"
}

$app = $root.SelectSingleNode("application")
$wanted = [ordered]@{ allowBackup = "false"; usesCleartextTraffic = "false"; taskAffinity = "" }
foreach ($name in $wanted.Keys) {
    if (-not $app.HasAttribute($name, $android) -or $app.GetAttribute($name, $android) -ne $wanted[$name]) {
        $problems += "the application's $name is not `"$($wanted[$name])`""
    }
}
if (-not $app.GetAttribute("dataExtractionRules", $android)) {
    $problems += "the application has no dataExtractionRules"
}

# What the app asks for (AndroidManifest.xml says why), and what the libraries add: the
# fingerprint's older name (AndroidX), the network's state (Play services' code scanner) and a
# permission of the app's own that keeps its receivers to itself (AndroidX).
$permissions = @(
    "android.permission.INTERNET",
    "android.permission.USE_BIOMETRIC",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.HIDE_OVERLAY_WINDOWS",
    "android.permission.USE_FINGERPRINT",
    "android.permission.ACCESS_NETWORK_STATE",
    "org.passwordvault.phone.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
)
$asked = @($root.SelectNodes("uses-permission") | ForEach-Object { $_.GetAttribute("name", $android) })
foreach ($name in $asked) {
    if ($permissions -notcontains $name) { $problems += "asks for $name" }
}
if ($asked -notcontains "android.permission.HIDE_OVERLAY_WINDOWS") {
    $problems += "doesn't ask for android.permission.HIDE_OVERLAY_WINDOWS"
}

# Exported, and who may reach it: the launcher screen anyone; the passkey and autofill
# services Android alone (a permission only the system holds); AndroidX's receiver of
# start-up profiles the shell alone (adb), to install a profile, nothing of the vault.
$open = @{
    "org.passwordvault.phone.VaultActivity" = ""
    "org.passwordvault.phone.VaultCredentialService" = "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE"
    "org.passwordvault.phone.VaultAutofillService" = "android.permission.BIND_AUTOFILL_SERVICE"
    "androidx.profileinstaller.ProfileInstallReceiver" = "android.permission.DUMP"
}
foreach ($kind in @("activity", "activity-alias", "service", "receiver", "provider")) {
    foreach ($part in $app.SelectNodes($kind)) {
        $name = $part.GetAttribute("name", $android)
        $exported = $part.GetAttribute("exported", $android)
        # Without the attribute a part with an intent filter would be exported (Android 12
        # refuses to install that from an app made for it, but say so all the same).
        $filters = $part.SelectNodes("intent-filter").Count
        $isOpen = $exported -eq "true" -or ($exported -eq "" -and $filters -gt 0)
        if (-not $isOpen) { continue }
        if (-not $open.ContainsKey($name)) {
            $problems += "$kind $name is open to other apps"
        } elseif ($part.GetAttribute("permission", $android) -ne $open[$name]) {
            $problems += "$kind $name is open to other apps without $($open[$name])"
        }
    }
}

if ($problems) {
    $problems | ForEach-Object { Write-Host "::error file=apps/mobile-android/AndroidManifest.xml::$_" }
    throw "the APK's manifest isn't as it should be ($($problems.Count) problems)"
}
Write-Host "The APK's manifest has its protections, the permissions listed and no other part open."
