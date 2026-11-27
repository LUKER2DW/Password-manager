# Checks that the app's native library loads on every Android it is for: each library it needs
# is one of Android's own (the APK ships no other), and each symbol it takes from them is in
# them at the lowest Android version the app installs on (minSdk, build.gradle). Android loads
# the library before the app's first line runs, so a missing symbol is a crash at start that no
# test on a computer shows (0.4.2 and 0.4.3: Skia, built with a newer NDK, needed a libc++
# function the older NDK's libc++ lacked).
#   check-library.ps1 -Library <libvault_mobile_android.so> -Ndk <NDK folder> [-Api 31]
# Run by build.ps1 and .github/workflows/release.yml; pwsh on Linux too.
param(
    [Parameter(Mandatory)] [string]$Library,
    [Parameter(Mandatory)] [string]$Ndk,
    [string]$Triple = "aarch64-linux-android",
    [int]$Api = 31
)
$ErrorActionPreference = "Stop"
$hostTag = if ($IsLinux) { "linux-x86_64" } elseif ($IsMacOS) { "darwin-x86_64" } else { "windows-x86_64" }
$llvm = Join-Path $Ndk "toolchains/llvm/prebuilt/$hostTag"
$exe = if ($IsLinux -or $IsMacOS) { "" } else { ".exe" }
$nm = Join-Path $llvm "bin/llvm-nm$exe"
$readelf = Join-Path $llvm "bin/llvm-readelf$exe"
$system = Join-Path $llvm "sysroot/usr/lib/$Triple/$Api"
if (-not (Test-Path $system)) { throw "the NDK at $Ndk has no libraries for Android API $Api" }

$needed = & $readelf -d $Library | ForEach-Object {
    if ($_ -match '\(NEEDED\)\s+Shared library: \[(.+)\]') { $Matches[1] }
}
if ($LASTEXITCODE -ne 0) { throw "llvm-readelf failed on $Library" }

$problems = @()
$provided = [System.Collections.Generic.HashSet[string]]::new()
foreach ($lib in $needed) {
    $stub = Join-Path $system $lib
    if (-not (Test-Path $stub)) {
        $problems += "needs $lib, which isn't one of Android's own libraries at API $Api"
        continue
    }
    foreach ($line in & $nm -D --defined-only $stub) {
        # "<address> T name@@VERSION": the name without its version.
        if ($line -match '\s[A-Za-z]\s+([^@\s]+)') { [void]$provided.Add($Matches[1]) }
    }
}

$missing = foreach ($line in & $nm -D --undefined-only $Library) {
    # A weak symbol (w, v) may be missing: the code asks whether it is there.
    if ($line -match '^\s*U\s+([^@\s]+)' -and -not $provided.Contains($Matches[1])) { $Matches[1] }
}
if ($LASTEXITCODE -ne 0) { throw "llvm-nm failed on $Library" }
foreach ($name in $missing) { $problems += "takes $name, which no library it loads has at API $Api" }

if ($problems.Count -gt 0) {
    $problems | ForEach-Object { Write-Host "  $_" }
    throw "$(Split-Path -Leaf $Library) wouldn't load on Android: $($problems.Count) problem(s), listed above"
}
Write-Host "$(Split-Path -Leaf $Library): loads on Android $Api and later ($($needed.Count) system libraries, every symbol found)."
