# Checks that Windows programs carry the exploit protections the build turns on: ASLR with a
# high-entropy address space, DEP, Control Flow Guard, and DLLs they import looked for in
# System32 only, never next to the exe (DependentLoadFlags, /DEPENDENTLOADFLAG:0x800: an exe run
# from Downloads ignores a DLL dropped there) (.cargo/config.toml). The release runs
# it on every exe before publishing (.github/workflows/release.yml), so a build that lost one
# (a RUSTFLAGS that replaced the config's flags, a changed linker) never ships.
#
#   apps/desktop/check-exe.ps1 -Exe target/release/vault-desktop.exe, target/release/vault.exe
param(
    [Parameter(Mandatory)][string[]]$Exe
)

$ErrorActionPreference = "Stop"

# IMAGE_OPTIONAL_HEADER64.DllCharacteristics
$highEntropyVa = 0x0020
$dynamicBase = 0x0040
$nxCompat = 0x0100
$guardCf = 0x4000
# IMAGE_LOAD_CONFIG_DIRECTORY64.GuardFlags
$cfInstrumented = 0x00000100
$cfFunctionTablePresent = 0x00000400
# IMAGE_LOAD_CONFIG_DIRECTORY64.DependentLoadFlags: LOAD_LIBRARY_SEARCH_SYSTEM32
$searchSystem32 = 0x0800

function Get-FileOffset([byte[]]$Bytes, [int]$SectionTable, [int]$Sections, [uint32]$Rva) {
    for ($i = 0; $i -lt $Sections; $i++) {
        $section = $SectionTable + 40 * $i
        $virtualSize = [BitConverter]::ToUInt32($Bytes, $section + 8)
        $virtualAddress = [BitConverter]::ToUInt32($Bytes, $section + 12)
        $rawSize = [BitConverter]::ToUInt32($Bytes, $section + 16)
        $rawOffset = [BitConverter]::ToUInt32($Bytes, $section + 20)
        $span = [Math]::Max($virtualSize, $rawSize)
        if ($Rva -ge $virtualAddress -and $Rva -lt $virtualAddress + $span) {
            return [int]($Rva - $virtualAddress + $rawOffset)
        }
    }
    throw "RVA $('0x{0:x}' -f $Rva) is in no section"
}

$failed = $false
foreach ($path in $Exe) {
    $name = Split-Path $path -Leaf
    $bytes = [IO.File]::ReadAllBytes((Resolve-Path $path))
    $pe = [BitConverter]::ToInt32($bytes, 0x3C)
    if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) { throw "${name}: not a PE file" }
    $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $pe + 20)
    $optional = $pe + 24
    if ([BitConverter]::ToUInt16($bytes, $optional) -ne 0x20B) { throw "${name}: not a 64-bit program" }
    $dll = [BitConverter]::ToUInt16($bytes, $optional + 70)

    $missing = @()
    if (-not ($dll -band $dynamicBase)) { $missing += "ASLR (DYNAMIC_BASE)" }
    if (-not ($dll -band $highEntropyVa)) { $missing += "high-entropy ASLR (HIGH_ENTROPY_VA)" }
    if (-not ($dll -band $nxCompat)) { $missing += "DEP (NX_COMPAT)" }
    if (-not ($dll -band $guardCf)) { $missing += "Control Flow Guard (GUARD_CF)" }

    # Data directory 10, the load configuration: where the guard's table of valid call targets is.
    $directory = $optional + 112 + 8 * 10
    $configRva = [BitConverter]::ToUInt32($bytes, $directory)
    $functions = 0
    if ($configRva -eq 0) {
        $missing += "a load configuration (Control Flow Guard's table)"
    } else {
        $config = Get-FileOffset $bytes ($optional + $optionalSize) $sections $configRva
        $configSize = [BitConverter]::ToUInt32($bytes, $config)
        if ($configSize -lt 148) {
            $missing += "Control Flow Guard's fields in the load configuration"
        } else {
            $loadFlags = [BitConverter]::ToUInt16($bytes, $config + 78)
            if (-not ($loadFlags -band $searchSystem32)) { $missing += "imported DLLs looked for in System32 only (DependentLoadFlags)" }
            $functions = [BitConverter]::ToUInt64($bytes, $config + 136)
            $guardFlags = [BitConverter]::ToUInt32($bytes, $config + 144)
            if (-not ($guardFlags -band $cfInstrumented)) { $missing += "calls checked by Control Flow Guard (CF_INSTRUMENTED)" }
            if (-not ($guardFlags -band $cfFunctionTablePresent) -or $functions -eq 0) {
                $missing += "Control Flow Guard's table of functions"
            }
        }
    }

    if ($missing) {
        Write-Host "${name}: lacks $($missing -join ', ')"
        $failed = $true
    } else {
        Write-Host "${name}: ASLR (high entropy), DEP, Control Flow Guard ($functions functions may be called indirectly), DLLs from System32"
    }
}
if ($failed) { throw "A program lacks a protection the build should give it." }
