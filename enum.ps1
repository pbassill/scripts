<# 
.SYNOPSIS
  System & Service Enumeration (PoC) – safe, read-only.

.DESCRIPTION
  Gathers detailed information about Windows services and processes from a non-privileged user context.
  Outputs a narrative summary (TXT) and several CSVs:
    - services_all.csv            : all services with rich metadata (state, start mode, account, path, PID, signature, hash)
    - services_running.csv        : subset of running services
    - services_potentially_writable.csv : services whose binary or parent directory appears user-writable (heuristic)
    - processes_all.csv           : all processes with key details
    - inventory.json              : compact JSON snapshot (services + processes)

  This PoC is non-destructive and illustrates why unrestricted PowerShell provides substantial reconnaissance value.

.PARAMETER OutputPath
  Optional. Directory to receive outputs. Defaults to Desktop\PS-Enum-<timestamp>.

.EXAMPLE
  .\ps-enum-services.ps1
  .\ps-enum-services.ps1 -OutputPath "C:\Temp\ps-enum"

.NOTES
  Designed for standard user execution. Requires PowerShell 5+ (works in Windows PowerShell and PowerShell 7).
#>

[CmdletBinding()]
param(
  [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath ("Desktop\PS-Enum-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")))
)

# region Helpers

function New-OutputFolder {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Get-NormalisedPath {
  param([string]$RawPath)
  if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }
  # Services often have quoted exe path + arguments; extract the executable portion.
  $p = $RawPath.Trim()
  if ($p.StartsWith('"')) {
    # Quoted path
    $end = $p.IndexOf('"',1)
    if ($end -gt 1) { return $p.Substring(1, $end-1) }
  }
  # Split on first space; crude but effective for typical cases
  $firstSpace = $p.IndexOf(' ')
  if ($firstSpace -gt 0) { return $p.Substring(0, $firstSpace) }
  return $p
}

function Test-WorldWritable {
  <#
    Returns an object indicating whether BUILTIN\Users or Everyone appear to have Write/Modify style rights
    on the given file and on its parent directory. This is a heuristic for demo/reporting purposes and not
    a full ACL audit.
  #>
  param([string]$TargetPath)

  $result = [pscustomobject]@{
    FileExists            = $false
    FileWritableByUsers   = $false
    FileWritableByEveryone= $false
    DirWritableByUsers    = $false
    DirWritableByEveryone = $false
    Reason                = $null
  }

  try {
    if (-not (Test-Path -LiteralPath $TargetPath)) { $result.Reason = "File not found"; return $result }
    $result.FileExists = $true

    $fileAcl = Get-Acl -LiteralPath $TargetPath -ErrorAction Stop
    $dirAcl  = Get-Acl -LiteralPath (Split-Path -LiteralPath $TargetPath -Parent) -ErrorAction Stop

    $writeMasks = @('Write','Modify','FullControl','WriteData','CreateFiles','AppendData','WriteAttributes','WriteExtendedAttributes')

    foreach ($ace in $fileAcl.Access) {
      if ($ace.IdentityReference -match 'Everyone' -and $ace.FileSystemRights.ToString().Split(',') | Where-Object { $_.Trim() -in $writeMasks }) { $result.FileWritableByEveryone = $true }
      if ($ace.IdentityReference -match 'Users'    -and $ace.FileSystemRights.ToString().Split(',') | Where-Object { $_.Trim() -in $writeMasks }) { $result.FileWritableByUsers    = $true }
    }
    foreach ($ace in $dirAcl.Access) {
      if ($ace.IdentityReference -match 'Everyone' -and $ace.FileSystemRights.ToString().Split(',') | Where-Object { $_.Trim() -in $writeMasks }) { $result.DirWritableByEveryone = $true }
      if ($ace.IdentityReference -match 'Users'    -and $ace.FileSystemRights.ToString().Split(',') | Where-Object { $_.Trim() -in $writeMasks }) { $result.DirWritableByUsers    = $true }
    }
  } catch {
    $result.Reason = "ACL read error: $($_.Exception.Message)"
  }

  return $result
}

function Get-FileMetadata {
  param([string]$Path)
  $meta = [pscustomobject]@{
    Exists        = $false
    CompanyName   = $null
    FileVersion   = $null
    ProductName   = $null
    SHA256        = $null
    Signature     = $null
    Signer        = $null
    SignatureStatus = $null
  }

  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $meta }

  try {
    $meta.Exists = $true
    $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    $meta.CompanyName = $fvi.CompanyName
    $meta.FileVersion = $fvi.FileVersion
    $meta.ProductName = $fvi.ProductName
  } catch {}

  try {
    $meta.SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path -ErrorAction Stop).Hash
  } catch {
    $meta.SHA256 = "HASH_ERROR: $($_.Exception.Message)"
  }

  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    $meta.Signature       = if ($sig.SignerCertificate) { 'Present' } else { 'None' }
    $meta.Signer          = $sig.SignerCertificate.Subject -replace '^CN=',''
    $meta.SignatureStatus = $sig.Status.ToString()
  } catch {
    $meta.Signature       = 'Unknown'
    $meta.SignatureStatus = "SIG_ERROR: $($_.Exception.Message)"
  }

  return $meta
}

# endregion Helpers

# region Preparation
$ErrorActionPreference = 'Stop'
New-OutputFolder -Path $OutputPath
$summaryPath = Join-Path $OutputPath 'summary.txt'
$svcAllCsv   = Join-Path $OutputPath 'services_all.csv'
$svcRunCsv   = Join-Path $OutputPath 'services_running.csv'
$svcWriteCsv = Join-Path $OutputPath 'services_potentially_writable.csv'
$procAllCsv  = Join-Path $OutputPath 'processes_all.csv'
$jsonPath    = Join-Path $OutputPath 'inventory.json'

"PowerShell Enumeration (read-only) started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')" | Out-File -FilePath $summaryPath -Encoding UTF8
"Output folder: $OutputPath" | O
