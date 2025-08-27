# setup.ps1
# Bot klasörü sabit: main.py'yi buradan çalıştıracağız
$BotDir = "C:\Users\Administrator\Desktop\bot"

# Güvenlik politikası (yalnızca CurrentUser)
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

# Klasöre geç
Set-Location $BotDir

# .venv yoksa oluştur
if (-not (Test-Path ".venv")) {
  py -3 -m venv .venv
}

# Pip'i güncelle ve ihtiyaçları kur (venv içindeki python ile)
$PyExe  = Join-Path $BotDir ".venv\Scripts\python.exe"
& $PyExe -m pip install --upgrade pip
$packages = @("PySide6","selenium","webdriver-manager","psutil","requests")
foreach ($p in $packages) { & $PyExe -m pip install --upgrade $p }

# Çalıştırma yardımcıları (isteğe bağlı)
if (-not (Test-Path "run.bat")) {
@'
@echo off
setlocal
cd /d "%~dp0"
call ".venv\Scripts\activate.bat"
start "" ".venv\Scripts\pythonw.exe" main.py
endlocal
'@ | Out-File -Encoding ASCII run.bat
}

if (-not (Test-Path "run_hidden.vbs")) {
@'
Set fso = CreateObject("Scripting.FileSystemObject")
folder = fso.GetParentFolderName(WScript.ScriptFullName)
cmd = "cmd /c """ & folder & "\run.bat"""
CreateObject("Wscript.Shell").Run cmd, 0, False
'@ | Out-File -Encoding ASCII run_hidden.vbs
}

# --- İSTENEN: main.py'yi hemen başlat ---
$PywExe = Join-Path $BotDir ".venv\Scripts\pythonw.exe"
if (-not (Test-Path $PywExe)) { $PywExe = $PyExe }   # yedek: konsollu python

# Konsolsuz başlat (çalışma dizini bot klasörü)
Start-Process -FilePath $PywExe -ArgumentList "main.py" -WorkingDirectory $BotDir -WindowStyle Hidden

Write-Host "`nKurulum bitti ve main.py başlatıldı. Sonraki seferler için 'run_hidden.vbs' dosyasına çift tıklayabilirsiniz." -ForegroundColor Green
