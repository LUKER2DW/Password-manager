# Copies Slint's Android backend (i-slint-backend-android-activity) of the given version from
# cargo's registry into vendor/i-slint-backend-android-activity, and makes the app's one change
# to it again (vendor/README.md). Run after a Slint update, which the workspace's [patch]
# would otherwise stop using without a word (apps/mobile's tests then fail):
#   1. bump Slint in Cargo.toml; cargo fetch (cargo warns that the patch isn't used);
#   2. vendor/update-slint-android.ps1 -Version <the new version>;
#   3. build the APK (apps/mobile-android/build.ps1) and run the tests.
param([Parameter(Mandatory)] [string]$Version)
$ErrorActionPreference = "Stop"
$name = "i-slint-backend-android-activity"
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $HOME ".cargo" }
$source = Get-ChildItem (Join-Path $cargoHome "registry/src") -Directory |
    ForEach-Object { Join-Path $_.FullName "$name-$Version" } |
    Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $source) { throw "$name $Version isn't in cargo's registry: run cargo fetch first" }

$target = Join-Path $PSScriptRoot $name
Remove-Item -Recurse -Force $target -ErrorAction SilentlyContinue
New-Item -ItemType Directory $target | Out-Null
# The crate as published (its Cargo.toml already has the workspace's fields filled in), without
# cargo's own bookkeeping and the lock file a dependency's build never reads.
Get-ChildItem $source -Force | Where-Object { $_.Name -notin ".cargo-ok", ".cargo_vcs_info.json", "Cargo.lock", "Cargo.toml.orig" } |
    Copy-Item -Destination $target -Recurse

# The change: every field the keyboard serves asks it not to learn what is typed (Gboard's
# incognito mode, and any keyboard that honours the flag), not only the password fields.
$java = Join-Path $target "java/SlintAndroidJavaHelper.java"
$text = [System.IO.File]::ReadAllText($java)
$before = "outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI;"
$after = "outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_EXTRACT_UI" +
    "`n                | EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING; // vault: the keyboard learns nothing"
$count = ([regex]::Matches($text, [regex]::Escape($before))).Count
if ($count -ne 1) { throw "the line to change is in SlintAndroidJavaHelper.java $count times, not once: look at the new version by hand" }
[System.IO.File]::WriteAllText($java, $text.Replace($before, $after))
Write-Host "vendor/$name is Slint's $Version with the keyboard's flag. Now: the patch's version in Cargo.toml, build.ps1, tests."
