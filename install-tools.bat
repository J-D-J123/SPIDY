@echo off
REM ===========================================================================
REM  Spidy companion toolkit installer (Windows)
REM
REM  Installs the Windows-friendly open-source recon/scanning tools into
REM  .\tools (self-contained): the Go/Rust binaries and the Python tools.
REM  Tools that need Perl/Ruby/bash (nikto, testssl.sh, whatweb, wpscan) are
REM  best run under WSL - install WSL (wsl --install) and use install-tools.sh.
REM
REM  These are third-party tools downloaded from their official GitHub repos.
REM  Review before running. Only scan systems you are authorized to test.
REM
REM  Requires: Windows 10/11 (bundled curl + tar), PowerShell, and Python
REM  (for wafw00f/sslyze). Run from this folder:  install-tools.bat
REM ===========================================================================
setlocal
set "ROOT=%~dp0"
set "TOOLS=%ROOT%tools"
set "BIN=%TOOLS%\bin"
if not exist "%BIN%" mkdir "%BIN%"

echo == Downloading prebuilt binaries (Go / Rust) ==
REM Delegate the GitHub-release resolution, download and extraction to PowerShell.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Continue';" ^
  "$bin='%BIN%';" ^
  "function GhInstall($repo,$rx,$name){" ^
  "  $exe=Join-Path $bin ($name+'.exe');" ^
  "  if(Test-Path $exe){Write-Host ('   ok (present): '+$name);return}" ^
  "  Write-Host ('>> '+$name+'  ('+$repo+')');" ^
  "  try{$rel=Invoke-RestMethod -UseBasicParsing ('https://api.github.com/repos/'+$repo+'/releases/latest') -Headers @{'User-Agent'='spidy-installer'}}catch{Write-Host ('   skip: '+$name+' (api error)');return}" ^
  "  $asset=$rel.assets | Where-Object { $_.name -match $rx } | Select-Object -First 1;" ^
  "  if(-not $asset){Write-Host ('   skip: '+$name+' (no asset)');return}" ^
  "  $tmp=Join-Path $env:TEMP ([guid]::NewGuid());New-Item -ItemType Directory -Path $tmp | Out-Null;" ^
  "  $pkg=Join-Path $tmp $asset.name;" ^
  "  try{Invoke-WebRequest -UseBasicParsing $asset.browser_download_url -OutFile $pkg}catch{Write-Host ('   skip: '+$name+' (download failed)');return}" ^
  "  if($pkg -match '\.zip$'){Expand-Archive -Force $pkg $tmp}elseif($pkg -match '\.tar\.gz$|\.tgz$'){tar -xzf $pkg -C $tmp}" ^
  "  $found=Get-ChildItem -Path $tmp -Recurse -Filter ($name+'.exe') | Select-Object -First 1;" ^
  "  if($found){Copy-Item $found.FullName $exe -Force;Write-Host ('   installed: '+$name)}else{Write-Host ('   skip: '+$name+' (exe not found)')};" ^
  "  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }" ^
  "GhInstall 'projectdiscovery/nuclei'    'nuclei_.*_windows_amd64\.zip'    'nuclei';" ^
  "GhInstall 'projectdiscovery/httpx'     'httpx_.*_windows_amd64\.zip'     'httpx';" ^
  "GhInstall 'projectdiscovery/katana'    'katana_.*_windows_amd64\.zip'    'katana';" ^
  "GhInstall 'projectdiscovery/subfinder' 'subfinder_.*_windows_amd64\.zip' 'subfinder';" ^
  "GhInstall 'projectdiscovery/naabu'     'naabu_.*_windows_amd64\.zip'     'naabu';" ^
  "GhInstall 'projectdiscovery/dnsx'      'dnsx_.*_windows_amd64\.zip'      'dnsx';" ^
  "GhInstall 'lc/gau'                     'gau_.*_windows_amd64\.zip'       'gau';" ^
  "GhInstall 'ffuf/ffuf'                  'ffuf_.*_windows_amd64\.zip'      'ffuf';" ^
  "GhInstall 'OJ/gobuster'                'gobuster_.*[Ww]indows_x86_64\.(zip|7z)' 'gobuster';" ^
  "GhInstall 'owasp-amass/amass'          'amass_.*[Ww]indows_amd64\.zip'   'amass';" ^
  "GhInstall 'epi052/feroxbuster'         'x86_64-windows-feroxbuster\.(zip|exe\.zip)' 'feroxbuster';" ^
  "GhInstall 'bee-san/RustScan'           '.*x86_64.*windows.*\.(zip)'      'rustscan';"

echo.
echo == Python tools (wafw00f, sslyze) ==
where python >nul 2>&1
if %errorlevel%==0 (
  python -m venv "%TOOLS%\venv"
  call "%TOOLS%\venv\Scripts\activate.bat"
  python -m pip install --upgrade pip wafw00f sslyze dirsearch
  for %%T in (wafw00f sslyze dirsearch) do if exist "%TOOLS%\venv\Scripts\%%T.exe" copy /Y "%TOOLS%\venv\Scripts\%%T.exe" "%BIN%\%%T.exe" >nul
  call deactivate
  echo    wafw00f / sslyze / dirsearch installed to %BIN%
) else (
  echo    skip: wafw00f/sslyze - Python not found on PATH ^(install from python.org^)
)

echo.
echo ================= SUMMARY =================
echo Tools installed to: %BIN%
echo Add them to PATH for this session:
echo     set "PATH=%BIN%;%%PATH%%"
echo Make permanent:  setx PATH "%BIN%;%%PATH%%"
echo.
echo Perl/Ruby/bash tools (nikto, testssl.sh, whatweb, wpscan) need WSL:
echo     wsl --install   then run  bash install-tools.sh  inside WSL.
echo Delete the .\tools folder to uninstall.
endlocal
