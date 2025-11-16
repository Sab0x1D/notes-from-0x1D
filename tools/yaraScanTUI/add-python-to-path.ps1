Param(
  [ValidateSet("User","System")]
  [string]$Scope = "User"
)

function Write-Info($msg){ Write-Host $msg -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host $msg -ForegroundColor Yellow }
function Write-Err ($msg){ Write-Host $msg -ForegroundColor Red }

function Get-PythonExe {
  try {
    if (Get-Command py -ErrorAction SilentlyContinue) {
      $exe = & py -3 -c "import sys;print(sys.executable)" 2>$null
      if ($exe) { return $exe }
    }
  } catch {}
  if (Get-Command python -ErrorAction SilentlyContinue) {
    return (Get-Command python).Source
  }
  $cands = @(
    "$env:LocalAppData\Programs\Python\Python3*\python.exe",
    "$env:LocalAppData\Programs\Python\Python*\python.exe",
    "$env:ProgramFiles\Python3*\python.exe",
    "$env:ProgramFiles\Python*\python.exe",
    "$env:ProgramFiles(x86)\Python*\python.exe"
  )
  foreach ($g in $cands) {
    $hit = Get-ChildItem -Path $g -ErrorAction SilentlyContinue |
           Sort-Object -Property LastWriteTime -Descending |
           Select-Object -First 1
    if ($hit) { return $hit.FullName }
  }
  return $null
}

function Get-PythonPaths($pythonExe){
  $basePrefix = & $pythonExe -c "import sys;print(sys.base_prefix)"
  if (-not $basePrefix) { $basePrefix = Split-Path -Parent $pythonExe }
  $bin     = $basePrefix.TrimEnd('\')
  $scripts = Join-Path $bin "Scripts"
  return ,$bin, $scripts
}

function Get-EnvPath([string]$target){
  return [Environment]::GetEnvironmentVariable("Path", $target)
}

function Set-EnvPath([string]$target, [string]$value){
  [Environment]::SetEnvironmentVariable("Path", $value, $target)
}

function Normalize-Entries([string[]]$entries){
  $seen = @{}; $out = New-Object System.Collections.Generic.List[string]
  foreach($e in $entries){
    if (!$e){ continue }
    $t = $e.Trim().TrimEnd('\')
    if ($t -and -not $seen.ContainsKey($t.ToLower())){
      $seen[$t.ToLower()] = $true
      $out.Add($t)
    }
  }
  return $out
}

if ($Scope -eq "System") {
  $currIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currIdentity)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "System scope requires an elevated PowerShell. Re-run as Administrator or use -Scope User."
    exit 1
  }
}

$python = Get-PythonExe
if (-not $python) {
  Write-Err "Python not found. Install Python 3.10+ first, then re-run."
  exit 1
}

$ver = & $python -c "import sys;print('.'.join(map(str,sys.version_info[:3])))"
Write-Info "Detected Python $ver at:`n  $python"

$bin,$scripts = Get-PythonPaths $python
if ($Scope -eq "System") { $targetScope = "Machine" } else { $targetScope = "User" }

$existing = Get-EnvPath $targetScope
$parts = @()
if ($existing) { $parts += $existing -split ';' }
$parts = Normalize-Entries $parts

$toAdd = @()
foreach($p in @($bin,$scripts)){
  if (-not (Test-Path $p)){
    Write-Warn "Skipping non-existent path: $p"
    continue
  }
  if (-not ($parts -contains $p)){
    $toAdd += $p
  }
}

if ($toAdd.Count -eq 0) {
  Write-Info "PATH already contains the required Python entries for $Scope scope."
} else {
  Write-Info "Adding to $Scope PATH:`n  $($toAdd -join "`n  ")"
  $newPath = ($parts + $toAdd) -join ';'
  Set-EnvPath $targetScope $newPath
  Write-Info "Updated $Scope PATH successfully."
}

# --- Update current session PATH cleanly ---
$sessionParts = ($env:Path -split ';') | ForEach-Object { $_.TrimEnd('\') }
$added = @()
foreach ($p in @($bin, $scripts)) {
  if (Test-Path $p) {
    $pt = $p.TrimEnd('\')
    if ($sessionParts -notcontains $pt) {
      $added += $pt
    }
  }
}
if ($added.Count -gt 0) {
  $env:Path = $env:Path + ';' + ($added -join ';')
  Write-Info "Updated current session PATH. You can use 'python' now without restarting."
} else {
  Write-Info "Current session PATH already included the entries."
}

Write-Host ""
Write-Host "Verify:" -ForegroundColor Green
Write-Host "  python --version" -ForegroundColor Green
Write-Host "  pip --version" -ForegroundColor Green
