[CmdletBinding()]
param(
    [string]$Msys2Root = 'C:\Users\Amamiya\Dev_ws\SDK\msys64',
    [ValidateSet('x64', 'x86', 'all')]
    [string]$Architecture = 'all',
    [switch]$Clean
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$sourceDir = Join-Path $projectRoot 'vendor\dropbear'
$outDir = Join-Path $projectRoot 'dist'
$bash = Join-Path $Msys2Root 'usr\bin\bash.exe'
$cygpath = Join-Path $Msys2Root 'usr\bin\cygpath.exe'

$targetDefinitions = @{
    x64 = [pscustomobject]@{
        Name = 'x64'
        ToolchainDir = 'mingw64'
        Host = 'x86_64-w64-mingw32'
        WinNt = '0x0502'
        SubsystemMajor = 5
        SubsystemMinor = 2
        PeFormat = 'pei-x86-64'
        OutputName = 'dropbear-win-x64.exe'
    }
    x86 = [pscustomobject]@{
        Name = 'x86'
        ToolchainDir = 'mingw32'
        Host = 'i686-w64-mingw32'
        WinNt = '0x0501'
        SubsystemMajor = 5
        SubsystemMinor = 1
        PeFormat = 'pei-i386'
        OutputName = 'dropbear-win-x86.exe'
    }
}

$selectedTargets = if ($Architecture -eq 'all') {
    @($targetDefinitions.x64, $targetDefinitions.x86)
} else {
    @($targetDefinitions[$Architecture])
}

foreach ($required in @($bash, $cygpath, (Join-Path $sourceDir 'configure'))) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Required build component not found: $required"
    }
}

function Assert-SafeBuildDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $rootFull = [IO.Path]::GetFullPath($projectRoot).TrimEnd('\')
    $pathFull = [IO.Path]::GetFullPath($Path)
    if (-not $pathFull.StartsWith("$rootFull\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Build directory is outside the project: $pathFull"
    }
}

function Assert-PeCompatibility {
    param(
        [Parameter(Mandatory)]$Target,
        [Parameter(Mandatory)][string]$Objdump,
        [Parameter(Mandatory)][string]$Executable
    )

    $peInfo = (& $Objdump -p $Executable 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "objdump failed for $Executable"
    }
    if ($peInfo -notmatch [regex]::Escape("file format $($Target.PeFormat)")) {
        throw "$Executable has the wrong PE architecture; expected $($Target.PeFormat)"
    }
    if ($peInfo -notmatch "MajorSubsystemVersion\s+$($Target.SubsystemMajor)(\s|$)" -or
            $peInfo -notmatch "MinorSubsystemVersion\s+$($Target.SubsystemMinor)(\s|$)") {
        throw "$Executable has the wrong subsystem version; expected $($Target.SubsystemMajor).$($Target.SubsystemMinor)"
    }
    if (-not [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($Executable)).Contains('requireAdministrator')) {
        throw "$Executable is missing the administrator request manifest"
    }

    $allowedDlls = @('ADVAPI32.dll', 'KERNEL32.dll', 'msvcrt.dll', 'WS2_32.dll')
    $importedDlls = [regex]::Matches($peInfo, 'DLL Name:\s*([^\r\n]+)') |
        ForEach-Object { $_.Groups[1].Value.Trim() } |
        Sort-Object -Unique
    $unexpectedDlls = @($importedDlls | Where-Object { $_ -notin $allowedDlls })
    if ($unexpectedDlls.Count -ne 0) {
        throw "$Executable imports non-XP or external runtime DLLs: $($unexpectedDlls -join ', ')"
    }

    $forbiddenImports = @(
        'InitOnceExecuteOnce',
        '_putenv_s',
        'BCrypt',
        'CreatePseudoConsole',
        'InitializeProcThreadAttributeList',
        'UpdateProcThreadAttribute',
        'GetSystemTimePreciseAsFileTime',
        'GetTickCount64',
        'CancelIoEx'
    )
    foreach ($forbidden in $forbiddenImports) {
        if ($peInfo -match [regex]::Escape($forbidden)) {
            throw "$Executable imports unsupported API $forbidden"
        }
    }
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$sourceUnix = (& $cygpath -u $sourceDir).Trim()
$windowsResourceUnix = (& $cygpath -u (Join-Path $projectRoot 'src\windows')).Trim()

$buildArtifacts = @()
foreach ($target in $selectedTargets) {
    $toolchainBin = Join-Path $Msys2Root "$($target.ToolchainDir)\bin"
    $strip = Join-Path $toolchainBin 'strip.exe'
    $objdump = Join-Path $toolchainBin 'objdump.exe'
    $gcc = Join-Path $toolchainBin 'gcc.exe'
    $windres = Join-Path $toolchainBin 'windres.exe'
    foreach ($required in @($gcc, $strip, $objdump, $windres)) {
        if (-not (Test-Path -LiteralPath $required)) {
            $hint = if ($target.Name -eq 'x86') {
                'Install it with: pacman -S --needed mingw-w64-i686-gcc mingw-w64-i686-binutils'
            } else {
                'Install the matching MSYS2 MinGW toolchain.'
            }
            throw "Required $($target.Name) build component not found: $required`n$hint"
        }
    }

    $buildDir = Join-Path $projectRoot "build\$($target.Name)"
    Assert-SafeBuildDirectory -Path $buildDir
    if ($Clean -and (Test-Path -LiteralPath $buildDir)) {
        Remove-Item -LiteralPath $buildDir -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null

    $buildUnix = (& $cygpath -u $buildDir).Trim()
    $sourceInclude = "$sourceUnix/src"
    $buildCFlags = "-O2 -fno-ident -ffunction-sections -fdata-sections -w " +
        "-I$sourceInclude -I$buildUnix " +
        "-DDISTROOPTIONS_H_EXISTS -DDROPBEAR_WIN32_NATIVE -DFD_SETSIZE=1024 " +
        "-D_WIN32_WINNT=$($target.WinNt) -DWINVER=$($target.WinNt)"
    $linkerFlags = "-static -static-libgcc -Wl,--gc-sections " +
        "-Wl,--major-os-version,$($target.SubsystemMajor),--minor-os-version,$($target.SubsystemMinor) " +
        "-Wl,--major-subsystem-version,$($target.SubsystemMajor),--minor-subsystem-version,$($target.SubsystemMinor)"
    $toolchainUnix = "/$($target.ToolchainDir)/bin"

    $buildCommands = @"
set -euo pipefail
test "`$MSYSTEM" = CLANG64
test "`$MSYS2_ROOT" = "`$MSYS2_HOME"
printf 'MSYSTEM=%s\nMSYS2_ROOT=%s\n' "`$MSYSTEM" "`$MSYS2_ROOT"
command -v bash
command -v clang
export PATH='${toolchainUnix}:/usr/bin'
cd '$buildUnix'
mkdir -p obj
python3 '$sourceUnix/../../scripts/embed-agent-bundle.py' '$buildUnix/agent-bundle.generated.h'
windres -I '$windowsResourceUnix' -i '$windowsResourceUnix/dropbear-win.rc' \
  -o '$buildUnix/obj/dropbear-win-manifest.o' -O coff
export ac_cv_c_undeclared_builtin_options='none needed'
export ac_cv_type_socklen_t=yes
export ac_cv_type_struct_sockaddr_storage=yes
export ac_cv_have_struct_sockaddr_storage=yes
export ac_cv_have_struct_sockaddr_in6=yes
export ac_cv_have_struct_in6_addr=yes
export ac_cv_have_struct_addrinfo=yes
export ac_cv_func_getaddrinfo=yes
export ac_cv_func_freeaddrinfo=yes
export ac_cv_func_getnameinfo=yes
if [ ! -f Makefile ]; then
sh '$sourceUnix/configure' \
  --host=$($target.Host) \
  --build=$($target.Host) \
  --enable-static \
  --enable-bundled-libtom \
  --disable-harden \
  --disable-zlib \
  --disable-pam \
  --disable-openpty \
  --disable-syslog \
  --disable-lastlog \
  --disable-utmp \
  --disable-utmpx \
  --disable-wtmp \
  --disable-wtmpx \
  --disable-loginfunc \
  --disable-pututline \
  --disable-pututxline \
  CPPFLAGS='-DDROPBEAR_WIN32_NATIVE -DFD_SETSIZE=1024 -D_WIN32_WINNT=$($target.WinNt) -DWINVER=$($target.WinNt) -include winsock2.h -include ws2tcpip.h' \
  CFLAGS='-O2 -fno-ident -ffunction-sections -fdata-sections' \
  LDFLAGS='$linkerFlags' \
  LIBS='-lws2_32 -ladvapi32'
elif [ '$sourceUnix/Makefile.in' -nt Makefile ]; then
  ./config.status Makefile
fi
make -j6 PROGRAMS='dropbear scp' MULTI=1 STATIC=1 \
  WIN_RESOURCE='$buildUnix/obj/dropbear-win-manifest.o' \
  CFLAGS='$buildCFlags' LDFLAGS='$linkerFlags'
"@

    $oldMsystem = $env:MSYSTEM
    $oldMsys2Root = $env:MSYS2_ROOT
    $oldMsys2Home = $env:MSYS2_HOME
    $oldChere = $env:CHERE_INVOKING
    try {
        $env:MSYSTEM = 'CLANG64'
        $env:MSYS2_ROOT = $Msys2Root
        $env:MSYS2_HOME = $Msys2Root
        $env:CHERE_INVOKING = '1'
        & $bash -lc $buildCommands
        if ($LASTEXITCODE -ne 0) {
            throw "Native $($target.Name) build failed with exit code $LASTEXITCODE"
        }
    } finally {
        $env:MSYSTEM = $oldMsystem
        $env:MSYS2_ROOT = $oldMsys2Root
        $env:MSYS2_HOME = $oldMsys2Home
        $env:CHERE_INVOKING = $oldChere
    }

    $builtExe = Join-Path $buildDir 'dropbearmulti.exe'
    $outputExe = Join-Path $outDir $target.OutputName
    if (-not (Test-Path -LiteralPath $builtExe)) {
        throw "Build completed without producing $builtExe"
    }
    Copy-Item -LiteralPath $builtExe -Destination $outputExe -Force
    & $strip -s $outputExe
    if ($LASTEXITCODE -ne 0) {
        throw "strip.exe failed for $outputExe"
    }
    Assert-PeCompatibility -Target $target -Objdump $objdump -Executable $outputExe

    $output = Get-Item -LiteralPath $outputExe
    $hashAlgorithm = [Security.Cryptography.SHA256]::Create()
    $hashStream = [IO.File]::OpenRead($outputExe)
    try {
        $hash = [BitConverter]::ToString($hashAlgorithm.ComputeHash($hashStream)).Replace('-', '')
    } finally {
        $hashStream.Dispose()
        $hashAlgorithm.Dispose()
    }
    Write-Host "Built:  $($output.FullName)"
    Write-Host "Target: $($target.Name), NT $($target.SubsystemMajor).$($target.SubsystemMinor)+"
    Write-Host "Size:   $($output.Length) bytes"
    Write-Host "SHA256: $hash"
    $buildArtifacts += [ordered]@{
        file = $target.OutputName
        architecture = $target.Name
        bytes = $output.Length
        sha256 = $hash
        minimumNt = "$($target.SubsystemMajor).$($target.SubsystemMinor)"
    }
}

[ordered]@{
    builtAtUtc = [DateTime]::UtcNow.ToString('o')
    artifacts = @($buildArtifacts)
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $outDir 'build-manifest.json') -Encoding UTF8
