# Makes the key that signs the phone app from now on. Android installs an update only when it
# is signed with the same key as the app already on the phone, and the app's own update check
# (Updates.java) asks for that too, so this key is what lets updates in, for good.
#
# It lives outside the repository, for this Windows user only:
#   %APPDATA%\PasswordVault\signing\release.p12   the key (PKCS#12, RSA 4096, alias "vault")
#   %APPDATA%\PasswordVault\signing\release.pass  its password, sealed with Windows DPAPI
# build.ps1 signs with it whenever it is there, and with the Android debug key otherwise.
#
# Afterwards:
# - Back up release.p12 and its password somewhere safe and offline (a password manager entry
#   and a USB stick, say). Lost, no update can ever be installed over the app again; copied,
#   whoever has it can sign an "update" the phone would take.
# - The first APK signed with it does not install over one signed with the debug key: sync or
#   export the vault, uninstall the old app once, then install the new one.
#
# Run it once: .\apps\mobile-android\make-release-key.ps1   (it asks for the password twice)
param(
    [string]$Dir = "$env:APPDATA\PasswordVault\signing",
    # Only for trying the script with a throwaway folder: the password, instead of asking.
    [securestring]$Password
)
$ErrorActionPreference = "Stop"
if (-not $env:JAVA_HOME) { $env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr" }
$keytool = Join-Path $env:JAVA_HOME "bin\keytool.exe"
$store = Join-Path $Dir "release.p12"
$sealed = Join-Path $Dir "release.pass"
if (Test-Path $store) {
    throw "$store exists already. A second key would lock every update out; remove that file yourself only if you are sure (and have no copy of the app signed with it to keep)."
}

if (-not $Password) {
    $Password = Read-Host "Password for the signing key (at least 12 characters)" -AsSecureString
    $again = Read-Host "The same password again" -AsSecureString
    $one = [System.Net.NetworkCredential]::new("", $Password).Password
    $two = [System.Net.NetworkCredential]::new("", $again).Password
    $same = $one -ceq $two
    $one = $null; $two = $null
    if (-not $same) { throw "The two passwords differ: nothing was made." }
}
$plain = [System.Net.NetworkCredential]::new("", $Password).Password
if ($plain.Length -lt 12) { throw "The password is shorter than 12 characters: nothing was made." }

New-Item -ItemType Directory -Force $Dir | Out-Null
# keytool reads the password from the environment of this process only, never from its command
# line (which other programs can see).
$env:VAULT_SIGNING_PASSWORD = $plain
try {
    & $keytool -genkeypair -keystore $store -storetype PKCS12 -alias vault `
        -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=Password Vault" `
        -storepass:env VAULT_SIGNING_PASSWORD -keypass:env VAULT_SIGNING_PASSWORD | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "keytool failed: nothing was made" }
    # Sealed for this Windows user (DPAPI): build.ps1 opens it without asking.
    ConvertFrom-SecureString $Password | Set-Content -NoNewline -Encoding ascii $sealed
    $fingerprint = (& $keytool -list -v -keystore $store -storetype PKCS12 `
            -storepass:env VAULT_SIGNING_PASSWORD | Select-String "SHA256:") -replace ".*SHA256:\s*", ""
} catch {
    Remove-Item -Force $store, $sealed -ErrorAction SilentlyContinue
    throw
} finally {
    Remove-Item Env:\VAULT_SIGNING_PASSWORD -ErrorAction SilentlyContinue
    $plain = $null
}

Write-Host "Made $store"
Write-Host "Certificate SHA-256: $fingerprint"
Write-Host "Now back up release.p12 and its password offline. build.ps1 signs with this key from now on."
