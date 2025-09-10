<# 
.SYNOPSIS
  System & Service Enumeration (PoC) – safe, read-only.

.DESCRIPTION
  Gathers detailed information about Windows services and processes from a non-privileged user context.
  Outputs:
    - summary.txt
    - services_all.csv
    - services_running.csv
    - services_potentially_writable.csv
    - processes_all.csv
    - inventory.json

.NOTES
  Works in Windows PowerShell 5+ and PowerShell 7+. Read-only; no admin required.
#>

[CmdletBinding()]
param(
  [string]$OutputPath = (Join-Path -Path $env:USERPROFILE -ChildPath ("Desktop\PS-Enum-{0}" -f (Get-Date -Format "yyyyMMdd-HHmmss")))
)

# ========================
# Helpers
# ========================

function New-OutputFolder {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
  }
}

function Get-NormalisedPath {
  param([string]$RawPath)
  if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }
  $p = $RawPath.Trim()
  if ($p.StartsWith('"')) {
    $end = $p.IndexOf('"',1)
    if ($end -gt 1) { return $p.Substring(1, $end-1) }
  }
  $firstSpace = $p.IndexOf(' ')
  if ($firstSpace -gt 0) { return $p.Substring(0, $firstSpace) }
  return $p
}

function Test-WorldWritable {
  param([string]$TargetPath)

  $result = [pscustomobject]@{
    FileExists             = $false
    FileWritableByUsers    = $false
    FileWritableByEveryone = $false
    DirWritableByUsers     = $false
    DirWritableByEveryone  = $false
    Reason                 = $null
  }

  try {
    if (-not (Test-Path -LiteralPath $TargetPath)) { $result.Reason = "File not found"; return $result }
    $result.FileExists = $true

    $fileAcl = Get-Acl -LiteralPath $TargetPath -ErrorAction Stop
    $dirAcl  = Get-Acl -LiteralPath (Split-Path -LiteralPath $TargetPath -Parent) -ErrorAction Stop

    $writeMasks = @('Write','Modify','FullControl','WriteData','CreateFiles','AppendData','WriteAttributes','WriteExtendedAttributes')

    foreach ($ace in $fileAcl.Access) {
      $rights = $ace.FileSystemRights.ToString().Split(',') | ForEach-Object { $_.Trim() }
      if ($ace.IdentityReference -match 'Everyone' -and ($rights | Where-Object { $_ -in $writeMasks })) { $result.FileWritableByEveryone = $true }
      if ($ace.IdentityReference -match 'Users'    -and ($rights | Where-Object { $_ -in $writeMasks })) { $result.FileWritableByUsers    = $true }
    }
    foreach ($ace in $dirAcl.Access) {
      $rights = $ace.FileSystemRights.ToString().Split(',') | ForEach-Object { $_.Trim() }
      if ($ace.IdentityReference -match 'Everyone' -and ($rights | Where-Object { $_ -in $writeMasks })) { $result.DirWritableByEveryone = $true }
      if ($ace.IdentityReference -match 'Users'    -and ($rights | Where-Object { $_ -in $writeMasks })) { $result.DirWritableByUsers    = $true }
    }
  } catch {
    $result.Reason = "ACL read error: $($_.Exception.Message)"
  }

  return $result
}

function Get-FileMetadata {
  param([string]$Path)
  $meta = [pscustomobject]@{
    Exists          = $false
    CompanyName     = $null
    FileVersion     = $null
    ProductName     = $null
    SHA256          = $null
    Signature       = $null
    Signer          = $null
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
    $meta.Signer          = if ($sig.SignerCertificate) { ($sig.SignerCertificate.Subject -replace '^CN=','') } else { $null }
    $meta.SignatureStatus = $sig.Status.ToString()
  } catch {
    $meta.Signature       = 'Unknown'
    $meta.SignatureStatus = "SIG_ERROR: $($_.Exception.Message)"
  }

  return $meta
}

function Get-ProcessStartTimeSafe {
  param([System.Diagnostics.Process]$Process)
  try { return $Process.StartTime } catch { return $null }
}

# ========================
# Prep and paths
# ========================

$ErrorActionPreference = 'Stop'
New-OutputFolder -Path $OutputPath

$summaryPath = Join-Path $OutputPath 'summary.txt'
$svcAllCsv   = Join-Path $OutputPath 'services_all.csv'
$svcRunCsv   = Join-Path $OutputPath 'services_running.csv'
$svcWriteCsv = Join-Path $OutputPath 'services_potentially_writable.csv'
$procAllCsv  = Join-Path $OutputPath 'processes_all.csv'
$jsonPath    = Join-Path $OutputPath 'inventory.json'

"PowerShell Enumeration (read-only) started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')" | Out-File -FilePath $summaryPath -Encoding UTF8
"Output folder: $OutputPath" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"User: $env:USERNAME  | Computer: $env:COMPUTERNAME  | Domain: $env:USERDOMAIN" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"" | Out-File -FilePath $summaryPath -Append -Encoding UTF8

# ========================
# Services
# ========================

Write-Host "Enumerating services..."
$services = Get-CimInstance -ClassName Win32_Service | Sort-Object DisplayName

$svcRich = foreach ($s in $services) {
  $exePath = Get-NormalisedPath -RawPath $s.PathName
  $fileMeta = if ($exePath) { Get-FileMetadata -Path $exePath } else { [pscustomobject]@{} }
  $aclCheck = if ($exePath) { Test-WorldWritable -TargetPath $exePath } else { [pscustomobject]@{} }

  $pid = if ($s.ProcessId -and $s.ProcessId -ne 0) { [int]$s.ProcessId } else { $null }
  $proc = $null
  if ($pid) {
    try { $proc = Get-Process -Id $pid -ErrorAction Stop } catch {}
  }

  [pscustomobject]@{
    Name                  = $s.Name
    DisplayName           = $s.DisplayName
    State                 = $s.State
    Status                = $s.Status
    StartMode             = $s.StartMode
    StartName             = $s.StartName
    ServiceType           = $s.ServiceType
    CanPauseContinue      = $s.AcceptPause.ToString()
    CanStop               = $s.AcceptStop.ToString()
    ProcessId             = $pid
    ExePath               = $exePath
    ExeExists             = $fileMeta.Exists
    CompanyName           = $fileMeta.CompanyName
    ProductName           = $fileMeta.ProductName
    FileVersion           = $fileMeta.FileVersion
    SHA256                = $fileMeta.SHA256
    Signature             = $fileMeta.Signature
    SignatureStatus       = $fileMeta.SignatureStatus
    Signer                = $fileMeta.Signer
    FileWritable_Users    = $aclCheck.FileWritableByUsers
    FileWritable_Everyone = $aclCheck.FileWritableByEveryone
    DirWritable_Users     = $aclCheck.DirWritableByUsers
    DirWritable_Everyone  = $aclCheck.DirWritableByEveryone
    ACL_Reason            = $aclCheck.Reason
    CPU                   = if ($proc) { '{0:N2}' -f $proc.CPU } else { $null }
    WorkingSetMB          = if ($proc) { [math]::Round($proc.WorkingSet64/1MB,2) } else { $null }
    StartTime             = if ($proc) { Get-ProcessStartTimeSafe -Process $proc } else { $null }
  }
}

$svcRich | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcAllCsv
$svcRich | Where-Object { $_.State -eq 'Running' } | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcRunCsv
$svcRich | Where-Object {
  $_.FileWritable_Users -or $_.FileWritable_Everyone -or $_.DirWritable_Users -or $_.DirWritable_Everyone
} | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $svcWriteCsv

$runningCount = ($svcRich | Where-Object State -eq 'Running').Count
$totalCount   = $svcRich.Count

"Services enumerated: $totalCount (Running: $runningCount)" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"Services CSV: $svcAllCsv" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"Running services CSV: $svcRunCsv" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"Potentially writable services CSV: $svcWriteCsv" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"" | Out-File -FilePath $summaryPath -Append -Encoding UTF8

# ========================
# Processes
# ========================

Write-Host "Enumerating processes..."
$procs = Get-Process | Sort-Object ProcessName | ForEach-Object {
  $path = $null
  try { $path = $_.Path } catch {}
  $meta = if ($path) { Get-FileMetadata -Path $path } else { [pscustomobject]@{} }

  $start = Get-ProcessStartTimeSafe -Process $_

  [pscustomobject]@{
    PID             = $_.Id
    Name            = $_.ProcessName
    CPU             = '{0:N2}' -f $_.CPU
    WS_MB           = [math]::Round($_.WorkingSet64/1MB,2)
    StartTime       = $start
    Path            = $path
    CompanyName     = $meta.CompanyName
    ProductName     = $meta.ProductName
    FileVersion     = $meta.FileVersion
    SHA256          = $meta.SHA256
    Signature       = $meta.Signature
    SignatureStatus = $meta.SignatureStatus
    Signer          = $meta.Signer
  }
}

$procs | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $procAllCsv

"Processes enumerated: $($procs.Count)" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"Processes CSV: $procAllCsv" | Out-File -FilePath $summaryPath -Append -Encoding UTF8
"" | Out-File -FilePath $summaryPath -Append -Encoding UTF8

# ========================
# JSON snapshot
# ========================

Write-Host "Writing JSON inventory..."
$inventory = [pscustomobject]@{
  Hostname  = $env:COMPUTERNAME
  Username  = $env:USERNAME
  WhenUTC   = (Get-Date -Format "O")
  Services  = $svcRich
  Processes = $procs
}
$inventory | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
"JSON snapshot: $jsonPath" | Out-File -FilePath $summaryPath -Append -Encoding UTF8

"Enumeration complete." | Out-File -FilePath $summaryPath -Append -Encoding UTF8
Write-Host "`nCompleted. Outputs written to: $OutputPath" -ForegroundColor Green
