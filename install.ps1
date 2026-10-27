# assay installer for Windows (D148). Downloads this release's prebuilt
# binary for your architecture from the GitHub Release, verifies the
# release's checksums file against the project's signing key embedded below
# (D137), verifies the zip's SHA256 against that file, and installs the one
# binary. The counterpart of install.sh, for Windows PowerShell 5.1 and
# PowerShell 7, with nothing to install first.
#
#   irm https://raw.githubusercontent.com/kun9497/assay/<commit>/install.ps1 | iex
#
# The README names the commit each release was built from: pin that, not a
# branch or a tag -- a branch moves, and so can a tag; the commit cannot.
# This script installs the version it was published with ($DefaultVersion
# below); another release is still verified against the keys embedded here,
# so an older script cannot install a release signed by a key it predates.
#
# Options, as parameters when the script is run as a file, or from the
# environment when it is piped into iex:
#   -BinDir  / ASSAY_INSTALL_DIR   install directory
#                                  (default: %LOCALAPPDATA%\Programs\assay)
#   -Version / ASSAY_VERSION       a tag to install, e.g. v0.12.0
#   ASSAY_ARCH                     override the detected architecture
#
# It never runs anything it downloads; it only extracts one binary. A
# refusal is a terminating error, never `exit`, so a piped install that
# refuses does not close the caller's PowerShell window.
#
# The whole script is one script block invoked with the script's own
# arguments: `iex` runs text in the caller's scope, so a top-level param()
# or assignment would overwrite the caller's $Version or $BinDir and leave
# these functions defined in their session. Inside the block they are
# local. Its lines are not indented, because the release tooling and the
# harness find $DefaultVersion and the key block at the start of a line.
#
# ASCII only: Windows PowerShell 5.1 reads a script without a byte-order
# mark in the system code page.
& {
param(
    [string]$BinDir = $env:ASSAY_INSTALL_DIR,
    [string]$Version = $env:ASSAY_VERSION
)

# Set by scripts/prepare-release.sh in the commit a release is cut from.
$DefaultVersion = 'v0.11.0'
$Repo = 'kun9497/assay'

# The public keys this installer trusts, PEM, one per release signing key.
# Rotation: release N+1's script carries keys N and N+1; a later one drops N.
# BEGIN TRUSTED KEYS
$TrustedKeys = @'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIJp1pXQuHML8/s3OnIas+O/upoke
VxyV0PZvba/q+F7T/1S10tKP7JL5QUE9DXJZPcYDVWoCyvM0NfUJuNvv0Q==
-----END PUBLIC KEY-----
'@
# END TRUSTED KEYS

function Write-AssayNote([string]$Message) {
    [Console]::Error.WriteLine("assay: $Message")
}

# ConvertFrom-AssayDerSignature turns the DER ECDSA signature cosign
# sign-blob writes (SEQUENCE { INTEGER r, INTEGER s }) into the 64-byte r||s
# form .NET verifies, or returns $null for anything that is not one. Written
# out because Windows PowerShell 5.1's .NET has no DER signature format.
function ConvertFrom-AssayDerSignature([byte[]]$Der) {
    if ($Der.Length -lt 8 -or $Der[0] -ne 0x30 -or $Der[1] -ne ($Der.Length - 2)) { return $null }
    $out = New-Object byte[] 64
    $i = 2
    foreach ($half in 0, 1) {
        if ($i + 2 -gt $Der.Length -or $Der[$i] -ne 0x02) { return $null }
        $len = [int]$Der[$i + 1]
        $i += 2
        $end = $i + $len
        if ($len -lt 1 -or $len -gt 33 -or $end -gt $Der.Length) { return $null }
        # Canonical DER only, the encoding openssl (install.sh) and .NET's
        # own reader accept: not negative, and a leading zero only where the
        # next byte needs it.
        if (($Der[$i] -band 0x80) -ne 0) { return $null }
        if ($len -gt 1 -and $Der[$i] -eq 0 -and ($Der[$i + 1] -band 0x80) -eq 0) { return $null }
        $start = $i
        if ($Der[$start] -eq 0 -and $len -gt 1) { $start++ }
        $n = $end - $start
        if ($n -gt 32) { return $null }
        [Array]::Copy($Der, $start, $out, ($half * 32) + 32 - $n, $n)
        $i = $end
    }
    if ($i -ne $Der.Length) { return $null }
    return , $out
}

# Get-AssayVerifier imports one PEM P-256 public key. Windows PowerShell 5.1
# cannot read a SubjectPublicKeyInfo, so the key is taken from its fixed
# layout (a 26-byte header naming id-ecPublicKey and P-256, then 04||X||Y)
# and imported as a CNG public blob; any other shape returns $null.
function Get-AssayVerifier([string]$Pem) {
    $b64 = ($Pem -replace '-----[A-Z ]+-----', '') -replace '\s', ''
    try { $spki = [Convert]::FromBase64String($b64) } catch { return $null }
    $header = '3059301306072a8648ce3d020106082a8648ce3d030107034200'
    if ($spki.Length -ne 91) { return $null }
    $got = -join ($spki[0..25] | ForEach-Object { $_.ToString('x2') })
    # Equivalent under mutation for every key this script carries (all are
    # P-256, and no other curve's SPKI is 91 bytes with the point at 26);
    # kept so a wrong key added to the block is refused, not misread.
    if ($got -ne $header -or $spki[26] -ne 0x04) { return $null }
    $blob = New-Object byte[] 72
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x31534345), 0, $blob, 0, 4) # BCRYPT_ECDSA_PUBLIC_P256_MAGIC
    [Array]::Copy([BitConverter]::GetBytes([uint32]32), 0, $blob, 4, 4)
    [Array]::Copy($spki, 27, $blob, 8, 64)
    $cng = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    return New-Object Security.Cryptography.ECDsaCng($cng)
}

function Install-Assay([string]$BinDir, [string]$Version) {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue' # 5.1's progress bar slows a download tenfold
    Set-StrictMode -Version 2

    if (-not $Version) { $Version = $DefaultVersion }
    if ($Version -notmatch '^v\d+\.\d+\.\d+$') { throw "assay: '$Version' is not a release tag (want vX.Y.Z)" }
    if (-not $BinDir) { $BinDir = Join-Path $env:LOCALAPPDATA 'Programs\assay' }

    $arch = $env:ASSAY_ARCH
    if (-not $arch) {
        $arch = $env:PROCESSOR_ARCHITEW6432
        if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    }
    switch ($arch.ToLowerInvariant()) {
        { $_ -in 'amd64', 'x86_64' } { $arch = 'amd64'; break }
        { $_ -in 'arm64', 'aarch64' } { $arch = 'arm64'; break }
        default { throw "assay: no prebuilt binary for arch '$arch' -- try 'go install github.com/$Repo/cmd/assay@latest'" }
    }

    $pems = [regex]::Matches($TrustedKeys, '-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----') | ForEach-Object { $_.Value }
    if (-not $pems) { throw 'assay: this installer embeds no trusted key; it is not a published copy -- refusing to install' }

    $releaseBase = $env:ASSAY_RELEASE_BASE
    if (-not $releaseBase) { $releaseBase = "https://github.com/$Repo/releases/download" }
    # GoReleaser's archive names strip the leading 'v' from the version.
    $ver = $Version.Substring(1)
    $archive = "assay_${ver}_windows_${arch}.zip"
    $sums = "assay_${ver}_checksums.txt"
    $base = "$releaseBase/$Version"

    # TLS 1.2 is added only where the process pins an older list; the
    # system default (0) already negotiates 1.2 or 1.3 and must stay the
    # default. Process-wide, so it is put back afterwards either way.
    $tls = [Net.ServicePointManager]::SecurityProtocol
    if ([int]$tls -ne 0 -and ($tls -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
        [Net.ServicePointManager]::SecurityProtocol = $tls -bor [Net.SecurityProtocolType]::Tls12
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('assay-install-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Write-AssayNote "downloading $archive ($Version)"
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$archive" -OutFile (Join-Path $tmp $archive)
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$sums" -OutFile (Join-Path $tmp $sums)
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$sums.sig" -OutFile (Join-Path $tmp "$sums.sig")
        } catch {
            # Refused, never warned about: every release from the first
            # signed one onward attaches the signature, so a missing one is
            # a stripped one.
            throw "assay: $sums.sig is missing from the $Version release -- refusing to install an unsigned checksums file"
        }

        # --- verify the checksums file's signature ---------------------------
        $data = [IO.File]::ReadAllBytes((Join-Path $tmp $sums))
        $sig = $null
        try {
            $der = [Convert]::FromBase64String(([IO.File]::ReadAllText((Join-Path $tmp "$sums.sig"))).Trim())
            $sig = ConvertFrom-AssayDerSignature $der
        } catch { $sig = $null }
        $verified = $null
        if ($sig) {
            $n = 0
            foreach ($pem in $pems) {
                $n++
                $key = Get-AssayVerifier $pem
                if ($key -and $key.VerifyData($data, $sig, [Security.Cryptography.HashAlgorithmName]::SHA256)) {
                    $verified = "key$n"
                    break
                }
            }
        }
        if (-not $verified) {
            Write-AssayNote '  run the installer published with the release you want; see the README'
            throw "assay: signature on $sums does not verify against any key embedded in this installer ($DefaultVersion) -- refusing to install"
        }
        Write-AssayNote "signature on $sums verified ($verified)"

        # --- verify checksum -------------------------------------------------
        $expected = $null
        foreach ($line in [IO.File]::ReadAllLines((Join-Path $tmp $sums))) {
            if ($line -match '^([0-9a-fA-F]{64})\s+\*?(\S+)$' -and $Matches[2] -eq $archive) { $expected = $Matches[1].ToLowerInvariant() }
        }
        if (-not $expected) { throw "assay: $archive is not listed in $sums -- refusing to install unverified" }
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $tmp $archive)).Hash.ToLowerInvariant()
        if ($expected -ne $actual) {
            throw "assay: checksum mismatch for $archive (expected $expected, actual $actual)"
        }

        # --- install ---------------------------------------------------------
        $x = Join-Path $tmp 'x'
        Expand-Archive -LiteralPath (Join-Path $tmp $archive) -DestinationPath $x -Force
        $exe = Join-Path $x 'assay.exe'
        if (-not (Test-Path -LiteralPath $exe)) { throw "assay: $archive holds no assay.exe" }
        New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
        Copy-Item -LiteralPath $exe -Destination (Join-Path $BinDir 'assay.exe') -Force
    } finally {
        [Net.ServicePointManager]::SecurityProtocol = $tls
        Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue
    }

    Write-AssayNote "installed $Version to $(Join-Path $BinDir 'assay.exe')"
    $full = (Resolve-Path -LiteralPath $BinDir).Path
    $onPath = ($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $full.TrimEnd('\') }
    if (-not $onPath) {
        # A copy-pasteable next step rather than a description of one:
        # "assay is not recognized" right after a successful install is the
        # most likely question this script would otherwise leave behind.
        Write-AssayNote "$full is not on your PATH. To add it for your user (new windows pick it up):"
        Write-AssayNote "  [Environment]::SetEnvironmentVariable('Path', '$full;' + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
    }
}

Install-Assay -BinDir $BinDir -Version $Version
} @args
