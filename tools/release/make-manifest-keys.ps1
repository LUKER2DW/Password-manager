# Makes the two keys that sign the release manifest (docs/CODE_SIGNING.md, CRYPTO.md §9): the
# apps take a release only when its manifest.json is signed by one of them
# (vault_sync_wire::releases::RELEASE_KEYS), so these keys are what lets updates in.
#
# - The primary signs every release, in the release workflow: its secret half and password are
#   secrets of the `android-release` environment (-SetSecrets puts them there), like the APK's
#   key.
# - The backup never goes to GitHub: it stays on this computer, to replace the primary if that
#   one ever leaks (-SetSecrets -Backup, then a release whose RELEASE_KEYS drops the primary).
#
# They live outside the repository, for this Windows user only:
#   %APPDATA%\PasswordVault\signing\release-manifest.key         the primary's secret half,
#                                                                 sealed under its password
#   %APPDATA%\PasswordVault\signing\release-manifest.pass        that password, sealed with DPAPI
#   %APPDATA%\PasswordVault\signing\release-manifest.pub         its public half (minisign's)
#   %APPDATA%\PasswordVault\signing\release-manifest-backup.*    the same for the backup
# A .env at the repository's root (git-ignored; .env.example lists its keys) may give the
# passwords (VAULT_MANIFEST_PASSWORD, VAULT_MANIFEST_BACKUP_PASSWORD) instead of asking for them,
# and the keys' places (VAULT_MANIFEST_KEY, VAULT_MANIFEST_BACKUP_KEY).
#
# Afterwards:
# - Put the two public keys it prints into RELEASE_KEYS (crates/sync-wire/src/releases.rs, with
#   their ids in the test that pins them) and docs/CODE_SIGNING.md, and release that.
# - Back up the folder and the two passwords somewhere safe and offline. Both keys lost: no
#   release is ever taken again by the apps that carry them; one copied with its password:
#   whoever has it can sign a release the apps take, until a release replaces it.
#
#   .\tools\release\make-manifest-keys.ps1                 makes both (asks for two passwords)
#   .\tools\release\make-manifest-keys.ps1 -SetSecrets     and puts the primary into GitHub
#   .\tools\release\make-manifest-keys.ps1 -SetSecrets -Backup   the backup in its place
# It builds tools/release with cargo, and -SetSecrets needs gh, signed in as the maintainer. No
# secret is ever printed or put on a command line.
param(
    [string]$Dir = "$env:APPDATA\PasswordVault\signing",
    [string]$Repository = "LUKER2DW/Password-manager",
    # Put the key into the `android-release` environment (RELEASE_MANIFEST_KEY and
    # RELEASE_MANIFEST_PASSWORD), making the keys first when there are none.
    [switch]$SetSecrets,
    # With -SetSecrets: the backup's key instead of the primary's.
    [switch]$Backup,
    # Only for trying the script with a throwaway folder: the passwords, instead of asking.
    [securestring]$Password,
    [securestring]$BackupPassword
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# The .env, read for this process only.
$fromDotEnv = @{}
$dotEnv = Join-Path $root ".env"
if (Test-Path $dotEnv) {
    foreach ($line in Get-Content $dotEnv) {
        if ($line -match '^\s*(VAULT_MANIFEST_(BACKUP_)?(KEY|PASSWORD))\s*=\s*(.*?)\s*$') {
            $fromDotEnv[$Matches[1]] = $Matches[4]
        }
    }
}

$keys = [ordered]@{}
foreach ($role in "primary", "backup") {
    $stem = if ($role -eq "primary") { "release-manifest" } else { "release-manifest-backup" }
    $var = if ($role -eq "primary") { "VAULT_MANIFEST" } else { "VAULT_MANIFEST_BACKUP" }
    $key = if ($fromDotEnv["${var}_KEY"]) { $fromDotEnv["${var}_KEY"] } else { Join-Path $Dir "$stem.key" }
    $keys[$role] = @{
        key = $key
        public = [IO.Path]::ChangeExtension($key, ".pub")
        sealed = [IO.Path]::ChangeExtension($key, ".pass")
        dotEnvPassword = $fromDotEnv["${var}_PASSWORD"]
        given = if ($role -eq "primary") { $Password } else { $BackupPassword }
    }
}
foreach ($role in $keys.Keys) {
    if ([IO.Path]::GetFullPath($keys[$role].key).StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "$($keys[$role].key) is inside the repository: a secret key never goes there."
    }
}

# The tool, built once (it reads a key's password from its own environment only).
Write-Host "Building tools/release..."
& cargo build --quiet --release --locked -p vault-release --manifest-path (Join-Path $root "Cargo.toml")
if ($LASTEXITCODE -ne 0) { throw "cargo build -p vault-release failed." }
$targetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $root "target" }
$tool = Join-Path $targetDir "release\vault-release.exe"

function Read-NewPassword([string]$Role) {
    $first = Read-Host "Password for the $Role manifest key (at least 12 characters)" -AsSecureString
    $again = Read-Host "The same password again" -AsSecureString
    $one = [System.Net.NetworkCredential]::new("", $first).Password
    $two = [System.Net.NetworkCredential]::new("", $again).Password
    $same = $one -ceq $two
    $one = $null; $two = $null
    if (-not $same) { throw "The two passwords differ: nothing more was made." }
    return $first
}

# Runs the tool with `$Plain` as the key's password, in this process's environment only.
function Invoke-Tool([string]$Plain, [string[]]$Arguments) {
    $env:VAULT_RELEASE_KEY_PASSWORD = $Plain
    try {
        $output = & $tool @Arguments
        if ($LASTEXITCODE -ne 0) { throw "vault-release $($Arguments[0]) failed." }
        return $output
    } finally {
        Remove-Item Env:\VAULT_RELEASE_KEY_PASSWORD -ErrorAction SilentlyContinue
    }
}

# A key's password: from .env, else sealed for this Windows user (DPAPI).
function Get-KeyPassword($Entry) {
    if ($Entry.dotEnvPassword) { return $Entry.dotEnvPassword }
    $sealed = (Get-Content -Raw $Entry.sealed).Trim()
    return [System.Net.NetworkCredential]::new("", (ConvertTo-SecureString $sealed)).Password
}

$have = @($keys.Values | Where-Object { Test-Path $_.key })
if ($have.Count -eq 1) {
    throw "Only one of the two keys is there ($($have[0].key)): look at what happened to the other before going on."
}
if ($have.Count -eq 0) {
    New-Item -ItemType Directory -Force $Dir | Out-Null
    $made = @()
    try {
        foreach ($role in $keys.Keys) {
            $entry = $keys[$role]
            foreach ($path in $entry.key, $entry.public, $entry.sealed) {
                if (Test-Path $path) { throw "$path exists already: nothing was made over it." }
            }
            $secure = if ($entry.given) { $entry.given }
                elseif ($entry.dotEnvPassword) { ConvertTo-SecureString $entry.dotEnvPassword -AsPlainText -Force }
                else { Read-NewPassword $role }
            $plain = [System.Net.NetworkCredential]::new("", $secure).Password
            try {
                if ($plain.Length -lt 12) { throw "The $role key's password is shorter than 12 characters: nothing more was made." }
                $made += $entry.key, $entry.public, $entry.sealed
                Invoke-Tool $plain @("new-key", "--key", $entry.key, "--public", $entry.public, "--name", $role) | Out-Null
            } finally {
                $plain = $null
            }
            ConvertFrom-SecureString $secure | Set-Content -NoNewline -Encoding ascii $entry.sealed
        }
    } catch {
        Remove-Item -Force $made -ErrorAction SilentlyContinue
        throw
    }
    Write-Host "Made the two manifest keys in $Dir."
}

# Each key checked with its password; the public halves printed for RELEASE_KEYS.
Write-Host ""
Write-Host "The public keys, for RELEASE_KEYS (crates/sync-wire/src/releases.rs) and docs/CODE_SIGNING.md:"
foreach ($role in $keys.Keys) {
    $entry = $keys[$role]
    $plain = Get-KeyPassword $entry
    try {
        $line = (Invoke-Tool $plain @("public-key", "--key", $entry.key) | Select-Object -Last 1).Trim()
    } finally {
        $plain = $null
    }
    $public, $id = $line -split ' '
    if ((Get-Content $entry.public)[1].Trim() -cne $public) { throw "$($entry.public) isn't the public half of $($entry.key)." }
    Write-Host ("  {0,-8} {1}  (key id {2})" -f $role, $public, $id)
}

if ($SetSecrets) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) { throw "gh isn't installed or on PATH." }
    $entry = if ($Backup) { $keys.backup } else { $keys.primary }
    $role = if ($Backup) { "backup" } else { "primary" }
    # Both through gh's standard input: never on a command line, never printed.
    [Convert]::ToBase64String([IO.File]::ReadAllBytes($entry.key)) |
        gh secret set RELEASE_MANIFEST_KEY --env android-release --repo $Repository
    if ($LASTEXITCODE -ne 0) { throw "gh secret set RELEASE_MANIFEST_KEY failed." }
    $plain = Get-KeyPassword $entry
    try {
        $plain | gh secret set RELEASE_MANIFEST_PASSWORD --env android-release --repo $Repository
        if ($LASTEXITCODE -ne 0) { throw "gh secret set RELEASE_MANIFEST_PASSWORD failed." }
    } finally {
        $plain = $null
    }
    Write-Host ""
    Write-Host "The $role key is in the android-release environment of $Repository now: the release workflow signs with it."
    if ($Backup) {
        Write-Host "Release a version whose RELEASE_KEYS no longer lists the old primary, and make a new backup."
    }
}
