Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# setup_and_run.ps1
# All-in-one setup and run script for AHE_SDK on Windows

$ErrorActionPreference = "Stop"

# Variables
$envName = "ahe_env"
$repoUrl = "https://github.com/hak3du/AHE_SDK.git"
$liboqsUrl = "https://github.com/open-quantum-safe/liboqs.git"
$liboqsPythonUrl = "https://github.com/open-quantum-safe/liboqs-python.git"
$workingDir = "$env:USERPROFILE\AHE_Setup"

Write-Host "`n[+] Creating working directory at $workingDir..."
New-Item -ItemType Directory -Path $workingDir -Force | Out-Null
Set-Location -Path $workingDir

Write-Host "`n[+] Creating Python virtual environment..."
python -m venv $envName

# Activate virtual environment in this script session
$venvScripts = Join-Path $workingDir "$envName\Scripts"
$activatePath = Join-Path $venvScripts "Activate.ps1"
Write-Host "`n[+] Activating virtual environment..."
. $activatePath

Write-Host "`n[+] Upgrading pip..."
pip install --upgrade pip

Write-Host "`n[+] Cloning AHE_SDK repo..."
if (Test-Path "AHE_SDK") {
    Remove-Item -Recurse -Force "AHE_SDK"
}
git clone $repoUrl
Set-Location -Path "$workingDir\AHE_SDK"

Write-Host "`n[+] Installing requirements..."
pip install -r requirements.txt

Write-Host "`n[+] Cleaning old liboqs and liboqs-python folders..."
Set-Location -Path $workingDir
if (Test-Path "liboqs") { Remove-Item -Recurse -Force "liboqs" }
if (Test-Path "liboqs-python") { Remove-Item -Recurse -Force "liboqs-python" }

Write-Host "`n[+] Cloning liboqs..."
git clone $liboqsUrl

Write-Host "`n[+] Cloning liboqs-python..."
git clone $liboqsPythonUrl

Write-Host "`n[+] Installing liboqs-python..."
Set-Location -Path "$workingDir\liboqs-python"
pip install .

Write-Host "`n[+] Starting FastAPI server using uvicorn..."
Set-Location -Path "$workingDir\AHE_SDK"

# Try to run uvicorn - api:app --reload
try {
    & "$venvScripts\uvicorn.exe" api:app --reload
}
catch {
    Write-Host "`n[!] uvicorn failed, trying fallback..."
    & python -m uvicorn web:api --reload

}
