# Refreshes the lists of sites that offer two-step sign-in with one-time codes and sites that
# take passkeys, which Password health compares the vault's logins with, offline
# (crates/core/data/sites-*.txt, read by crates/core/src/site_lists.rs).
#
# The data comes from 2FA Directory by 2factorauth (https://2fa.directory/, MIT licence) and
# from Passkeys Directory by 2factorauth (https://passkeys.2fa.directory/, CC BY 4.0). Run it
# by hand now and then and commit the result; the apps never fetch these lists themselves.
#
#   pwsh tools/site-lists/update.ps1
#
# Each line of a list is a site's domain, a tab, and the page that says how to turn the
# method on (https only; empty when the source gives none). Lines are sorted, one per domain.

$ErrorActionPreference = 'Stop'
$data = Join-Path $PSScriptRoot '..\..\crates\core\data'

function Get-Json([string] $url) {
    $answer = Invoke-WebRequest -Uri $url -UseBasicParsing -Headers @{ 'User-Agent' = 'site-list-update' }
    return $answer.Content | ConvertFrom-Json -AsHashtable
}

# A domain as the lists may hold it: lowercase letters, digits, dots and hyphens, two labels
# at least.
function Test-Domain([string] $domain) {
    return $domain -cmatch '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$'
}

function Get-Page($entry) {
    $page = [string] $entry['documentation']
    if ($page -like 'https://*' -and $page -notmatch '[\s\t"<>]') { return $page }
    return ''
}

function Write-List([string] $name, [hashtable] $lines) {
    $sorted = $lines.Keys | Sort-Object -Culture '' | ForEach-Object { "$_`t$($lines[$_])" }
    $path = Join-Path $data $name
    [System.IO.File]::WriteAllText($path, (($sorted -join "`n") + "`n"), [System.Text.UTF8Encoding]::new($false))
    Write-Host "$name`: $($lines.Count) sites"
}

# One-time codes: every site whose methods include "totp".
$totp = @{}
$sites = Get-Json 'https://api.2fa.directory/v4/totp.json'
foreach ($domain in $sites.Keys) {
    $entry = $sites[$domain]
    if ($entry['methods'] -notcontains 'totp') { continue }
    $key = $domain.ToLowerInvariant()
    if (Test-Domain $key) { $totp[$key] = Get-Page $entry }
}
Write-List 'sites-totp.txt' $totp

# Passkeys: every site that takes them, to sign in or as a second step, with its other domains.
$passkeys = @{}
$sites = Get-Json 'https://passkeys-api.2fa.directory/v1/supported.json'
foreach ($domain in $sites.Keys) {
    $entry = $sites[$domain]
    if (-not ($entry['passwordless'] -or $entry['mfa'])) { continue }
    $page = Get-Page $entry
    $names = @($domain) + @($entry['additional-domains'] | Where-Object { $_ })
    foreach ($name in $names) {
        $key = ([string] $name).ToLowerInvariant()
        if ((Test-Domain $key) -and -not $passkeys.ContainsKey($key)) { $passkeys[$key] = $page }
    }
}
Write-List 'sites-passkeys.txt' $passkeys
