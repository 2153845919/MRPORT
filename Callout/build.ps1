param(
    [string]$OutputDir = "."
)

$ErrorActionPreference = "Stop"

# Find MSVC
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -property installationPath | Select-Object -First 1
    $bat = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $bat) {
        # Run cl.exe via vcvars
        $cmd = "`"$bat`" && cl /nologo /O2 /MD callout.c /link /DLL /OUT:callout.dll /DEF:callout.def"
        cmd /c "`"$bat`" >nul 2>&1 && cl /nologo /O2 /MD callout.c /link /DLL /OUT:callout.dll /DEF:callout.def"
    }
}

if (-not (Test-Path "callout.dll")) {
    Write-Error "Failed to build callout.dll"
    exit 1
}

Copy-Item callout.dll $OutputDir
Write-Host "callout.dll built and copied to $OutputDir"
