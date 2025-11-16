Param()

# Run from script directory
Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Path)

# --- Locate Python ---------------------------------------------------------
# Prefer the launcher 'py -3', else fall back to 'python'
$PythonExe = $null
if (Get-Command py -ErrorAction SilentlyContinue) {
  try { $PythonExe = (& py -3 -c "import sys;print(sys.executable)") } catch {}
}
if (-not $PythonExe -and (Get-Command python -ErrorAction SilentlyContinue)) {
  $PythonExe = (Get-Command python).Source
}
if (-not $PythonExe) {
  Write-Error "Python not found. Please install Python 3.10+ and re-run."
  exit 1
}

# --- Version check >= 3.10 -------------------------------------------------
$pyVer = & $PythonExe -c "import sys;print('.'.join(map(str, sys.version_info[:3])))"
$maj,$min,$patch = $pyVer.Split('.')
if ([int]$maj -lt 3 -or ([int]$maj -eq 3 -and [int]$min -lt 10)) {
  Write-Error "Python $pyVer detected. Please use Python 3.10+."
  exit 1
}

# --- Venv + deps -----------------------------------------------------------
$venvPy      = ".\.venv\Scripts\python.exe"
$req         = ".\requirements.txt"
$reqHashFile = ".\.venv\.req.hash"

# Create venv if missing
if (-not (Test-Path $venvPy)) {
  Write-Host "Creating virtualenv ..." -ForegroundColor Cyan
  & $PythonExe -m venv ".\.venv"
}

# Upgrade core tooling inside venv
& $venvPy -m pip install --upgrade pip wheel setuptools | Out-Host

function Get-ReqHash {
  if (Test-Path $req) { (Get-FileHash $req -Algorithm SHA256).Hash } else { "" }
}

$currHash = Get-ReqHash
if (Test-Path $reqHashFile) { $prevHash = Get-Content $reqHashFile } else { $prevHash = "" }

if ($currHash -ne $prevHash) {
  Write-Host "Installing/updating dependencies ..." -ForegroundColor Cyan
  & $venvPy -m pip install -r $req | Out-Host
  $currHash | Out-File -FilePath $reqHashFile -Encoding ascii -Force
} else {
  Write-Host "Dependencies up to date." -ForegroundColor DarkGray
}

# --- Run app ---------------------------------------------------------------
& $venvPy .\scan_tui.py
