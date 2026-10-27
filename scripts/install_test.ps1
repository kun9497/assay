# Attack harness for install.ps1 (D148), the Windows counterpart of
# scripts/install_test.sh. Builds two fake releases signed with two test
# keys, serves them from a local python http.server, renders the installer
# with the test keys in place of the embedded ones, and runs every case
# under each PowerShell edition present (Windows PowerShell 5.1 and
# PowerShell 7), since the installer must verify on both. Each case asserts
# the exit code and a message substring. Run with PowerShell 7 from the
# repository root: pwsh -File scripts/install_test.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$repo = Split-Path -Parent $PSScriptRoot
$installer = if ($env:INSTALL_PS1) { $env:INSTALL_PS1 } else { Join-Path $repo 'install.ps1' }
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("assay-ps1-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$fail = $false
$arch = 'amd64'

# --- keys ---------------------------------------------------------------------
# PowerShell 7 (.NET 8+) makes and exports the test keys; the installer
# itself must not depend on any of these APIs, which 5.1 lacks.
$keys = @{}
foreach ($k in 'key1', 'key2', 'attacker') {
    $e = [Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $keys[$k] = $e
    Set-Content -Path (Join-Path $tmp "$k.pub") -Value $e.ExportSubjectPublicKeyInfoPem() -NoNewline
}

# --- fake releases ------------------------------------------------------------
# New-Release <tag> <key> <root> [label]: a zip holding assay.exe (whose bytes
# name the release, so the installed file can be checked), a GoReleaser
# checksums file, and the base64 DER signature cosign sign-blob writes.
function New-Release([string]$Tag, [string]$Key, [string]$Root, [string]$Label = 'genuine') {
    $ver = $Tag.TrimStart('v')
    $dir = Join-Path $Root $Tag
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $work = Join-Path $tmp "work-$Tag-$Label-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $work | Out-Null
    [IO.File]::WriteAllText((Join-Path $work 'assay.exe'), "assay $Tag ($Label build)")
    $zip = "assay_${ver}_windows_${arch}.zip"
    Compress-Archive -Path (Join-Path $work 'assay.exe') -DestinationPath (Join-Path $dir $zip) -Force
    $sums = "assay_${ver}_checksums.txt"
    $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $dir $zip)).Hash.ToLowerInvariant()
    # A second, unrelated line, as a real checksums file has one per asset.
    [IO.File]::WriteAllText((Join-Path $dir $sums), ("{0}  assay_{1}_linux_amd64.tar.gz`n{2}  {3}`n" -f ('0' * 64), $ver, $hash, $zip))
    $sig = $keys[$Key].SignData([IO.File]::ReadAllBytes((Join-Path $dir $sums)),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)
    [IO.File]::WriteAllText((Join-Path $dir "$sums.sig"), [Convert]::ToBase64String($sig))
}
$root = Join-Path $tmp 'releases'
New-Release v9.9.1 key1 $root
New-Release v9.9.2 key2 $root

# --- server -------------------------------------------------------------------
# Skipping WindowsApps: those are the Store's install-me stubs, not Python.
$py = (Get-Command python, python3 -CommandType Application -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -notlike '*\WindowsApps\*' } | Select-Object -First 1).Source
if (-not $py) { throw 'harness: need python' }
$l = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop()
$server = Start-Process -FilePath $py -ArgumentList '-m', 'http.server', $port, '--bind', '127.0.0.1' -WorkingDirectory $root -PassThru -WindowStyle Hidden
$base = "http://127.0.0.1:$port"

try {
    $up = $false
    foreach ($i in 1..50) {
        try { Invoke-WebRequest -UseBasicParsing -Uri "$base/" -TimeoutSec 2 | Out-Null; $up = $true; break } catch { Start-Sleep -Milliseconds 100 }
    }
    if (-not $up) { throw 'harness: server did not start' }

    # --- render installers ----------------------------------------------------
    # Render <out> <version> <keys...>: install.ps1 with $DefaultVersion set
    # and the embedded key block replaced by the given test keys.
    function Render([string]$Out, [string]$Version, [string[]]$KeyNames) {
        $src = [IO.File]::ReadAllText($installer)
        $begin = $src.IndexOf("# BEGIN TRUSTED KEYS`n"); $end = $src.IndexOf('# END TRUSTED KEYS')
        if ($begin -lt 0 -or $end -lt 0) { throw 'harness: install.ps1 lacks the TRUSTED KEYS markers' }
        $pems = ($KeyNames | ForEach-Object { [IO.File]::ReadAllText((Join-Path $tmp "$_.pub")) }) -join "`n"
        $block = "# BEGIN TRUSTED KEYS`n`$TrustedKeys = @'`n$pems`n'@`n"
        $rendered = $src.Substring(0, $begin) + $block + $src.Substring($end)
        $rendered = [regex]::Replace($rendered, '(?m)^\$DefaultVersion = .*$', "`$DefaultVersion = '$Version'")
        [IO.File]::WriteAllText($Out, $rendered)
    }
    Render (Join-Path $tmp 'install-k1.ps1') v9.9.1 @('key1')
    Render (Join-Path $tmp 'install-k12.ps1') v9.9.2 @('key1', 'key2')
    Render (Join-Path $tmp 'install-none.ps1') v9.9.1 @()

    # --- runner ---------------------------------------------------------------
    $shells = @(Get-Command pwsh, powershell -ErrorAction SilentlyContinue | ForEach-Object { $_.Source })
    function Run-Case([string]$Name, [string]$Script, [int]$Want, [string]$Needle, [string[]]$Extra = @(),
        [hashtable]$Env = @{}, [string]$Absent = '') {
        foreach ($sh in $shells) {
            $edition = [IO.Path]::GetFileNameWithoutExtension($sh)
            $bin = Join-Path $tmp "bin-$Name-$edition"
            if (Test-Path $bin) { Remove-Item -Recurse -Force $bin }
            $saved = @{}
            $Env['ASSAY_RELEASE_BASE'] = if ($Env.ContainsKey('ASSAY_RELEASE_BASE')) { $Env['ASSAY_RELEASE_BASE'] } else { $base }
            $Env['ASSAY_ARCH'] = $arch
            foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $Env[$k]) }
            try {
                $err = & $sh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script -BinDir $bin @Extra 2>&1 | Out-String
                $code = $LASTEXITCODE
            } finally {
                foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
            }
            if ($code -ne $Want -or -not $err.Contains($Needle) -or ($Absent -and $err.Contains($Absent))) {
                Write-Host "FAIL $Name [$edition]: exit=$code want=$Want; output:"; Write-Host ($err -replace '(?m)^', '    ')
                $script:fail = $true
            } else {
                Write-Host "ok   $Name [$edition] (exit $code)"
            }
            Set-Variable -Scope Script -Name lastBin -Value $bin
        }
    }
    function Assert-Installed([string]$Name, [string]$Want) {
        foreach ($sh in $shells) {
            $edition = [IO.Path]::GetFileNameWithoutExtension($sh)
            $exe = Join-Path (Join-Path $tmp "bin-$Name-$edition") 'assay.exe'
            $got = if (Test-Path $exe) { [IO.File]::ReadAllText($exe) } else { '<none>' }
            if ($got -ne $Want) { Write-Host "FAIL $Name [$edition]: installed '$got', want '$Want'"; $script:fail = $true }
        }
    }
    $k1 = Join-Path $tmp 'install-k1.ps1'
    $k12 = Join-Path $tmp 'install-k12.ps1'

    # C1 clean install
    Run-Case C1 $k1 0 'installed v9.9.1'
    Assert-Installed C1 'assay v9.9.1 (genuine build)'

    # C2 archive tampered, checksums and signature untouched
    Copy-Item -Recurse (Join-Path $root 'v9.9.1') (Join-Path $root 'c2\v9.9.1')
    $evil = Join-Path $tmp 'evil'; New-Item -ItemType Directory -Path $evil | Out-Null
    [IO.File]::WriteAllText((Join-Path $evil 'assay.exe'), 'EVIL')
    Compress-Archive -Path (Join-Path $evil 'assay.exe') -DestinationPath (Join-Path $root "c2\v9.9.1\assay_9.9.1_windows_$arch.zip") -Force
    Run-Case C2 $k1 1 'checksum mismatch' -Env @{ ASSAY_RELEASE_BASE = "$base/c2" }

    # C3a assets rewritten consistently by an attacker, the genuine .sig left
    New-Release v9.9.1 attacker (Join-Path $root 'c3a') EVIL
    Copy-Item (Join-Path $root 'v9.9.1\assay_9.9.1_checksums.txt.sig') (Join-Path $root 'c3a\v9.9.1\') -Force
    Run-Case C3a $k1 1 'does not verify against any key embedded' -Env @{ ASSAY_RELEASE_BASE = "$base/c3a" }

    # C3a-nosig: the .sig deleted -- refused by the missing-signature guard
    # itself, not by a later one.
    New-Release v9.9.1 attacker (Join-Path $root 'c3n') EVIL
    Remove-Item (Join-Path $root 'c3n\v9.9.1\assay_9.9.1_checksums.txt.sig')
    Run-Case C3a-nosig $k1 1 'is missing from the v9.9.1 release' -Env @{ ASSAY_RELEASE_BASE = "$base/c3n" } -Absent 'does not verify'

    # C3b: re-signed with the attacker's own key
    New-Release v9.9.1 attacker (Join-Path $root 'c3b') EVIL
    Run-Case C3b $k1 1 'does not verify against any key embedded' -Env @{ ASSAY_RELEASE_BASE = "$base/c3b" }

    # C3c: a signature that is not a DER ECDSA signature at all is a refusal,
    # not a crash and not a pass.
    Copy-Item -Recurse (Join-Path $root 'v9.9.1') (Join-Path $root 'c3c\v9.9.1')
    [IO.File]::WriteAllText((Join-Path $root 'c3c\v9.9.1\assay_9.9.1_checksums.txt.sig'), [Convert]::ToBase64String([byte[]](1..70)))
    Run-Case C3c $k1 1 'does not verify against any key embedded' -Env @{ ASSAY_RELEASE_BASE = "$base/c3c" }

    # C4: the archive is missing from a genuinely signed checksums file
    Copy-Item -Recurse (Join-Path $root 'v9.9.1') (Join-Path $root 'c4\v9.9.1')
    $sumsPath = Join-Path $root 'c4\v9.9.1\assay_9.9.1_checksums.txt'
    [IO.File]::WriteAllText($sumsPath, ('0' * 64) + "  assay_9.9.1_linux_amd64.tar.gz`n")
    [IO.File]::WriteAllText("$sumsPath.sig", [Convert]::ToBase64String($keys['key1'].SignData([IO.File]::ReadAllBytes($sumsPath),
        [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.DSASignatureFormat]::Rfc3279DerSequence)))
    Run-Case C4 $k1 1 'is not listed in' -Env @{ ASSAY_RELEASE_BASE = "$base/c4" }

    # C1-space: a temp directory with a space in its path
    $spaced = Join-Path $tmp 'sp ace'; New-Item -ItemType Directory -Path $spaced | Out-Null
    Run-Case C1-space $k1 0 'installed v9.9.1' -Env @{ TEMP = $spaced; TMP = $spaced }

    # C6 rotation: v9.9.2 is signed by key2
    Run-Case C6-new-script $k12 0 'installed v9.9.2'
    Run-Case C6-old-script $k1 1 'does not verify against any key embedded' -Extra @('-Version', 'v9.9.2')
    Run-Case C6-new-script-old-release $k12 0 'installed v9.9.1' -Extra @('-Version', 'v9.9.1')
    Assert-Installed C6-new-script-old-release 'assay v9.9.1 (genuine build)'

    # C10: the version lands in a URL, so only a release tag is accepted
    Run-Case C10 $k1 1 'is not a release tag' -Extra @('-Version', 'latest/../v9.9.1')

    # C8: a copy with no key at all refuses rather than trusting nothing
    Run-Case C8 (Join-Path $tmp 'install-none.ps1') 1 'embeds no trusted key'

    # C9: the piped form, `irm <url> | iex`, takes its options from the
    # environment and must not close the caller's session on a refusal.
    foreach ($sh in $shells) {
        $edition = [IO.Path]::GetFileNameWithoutExtension($sh)
        $bin = Join-Path $tmp "bin-C9-$edition"
        $cmd = "`$env:ASSAY_INSTALL_DIR='$bin'; `$env:ASSAY_RELEASE_BASE='$base'; `$env:ASSAY_ARCH='$arch'; " +
            "Get-Content -Raw '$k1' | Invoke-Expression; 'after-good'; " +
            "`$env:ASSAY_RELEASE_BASE='$base/c3b'; try { Get-Content -Raw '$k1' | Invoke-Expression } catch { 'caught: ' + `$_ }; 'session-alive'"
        $out = & $sh -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command $cmd 2>&1 | Out-String
        $exe = Join-Path $bin 'assay.exe'
        if (-not (Test-Path $exe) -or -not $out.Contains('after-good') -or -not $out.Contains('does not verify') -or -not $out.Contains('session-alive')) {
            Write-Host "FAIL C9 [$edition]:"; Write-Host ($out -replace '(?m)^', '    '); $fail = $true
        } else { Write-Host "ok   C9 [$edition] (piped install, refusal leaves the session)" }
    }

    # C7: the installer contacts nothing but the release base
    if ([IO.File]::ReadAllText($installer).Contains('api.github.com')) { Write-Host 'FAIL C7: install.ps1 calls api.github.com'; $fail = $true }
    else { Write-Host 'ok   C7 (no api.github.com call)' }

    if ($shells.Count -lt 2) {
        # In CI both editions are on the runner, and a run under one would
        # report 5.1 support it never exercised.
        if ($env:CI) { Write-Host "FAIL: only $($shells -join ', ') found; CI must run both editions"; $fail = $true }
        else { Write-Host "note: ran under $($shells -join ', ') only" }
    }
} finally {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
if ($fail) { Write-Host 'install.ps1 harness: FAILURES'; exit 1 }
Write-Host 'install.ps1 harness: all cases passed'
