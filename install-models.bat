@echo off
REM ---------------------------------------------------------------------------
REM Spidy local-model installer (Windows)
REM
REM Pulls the open, uncensored LLMs Spidy's Autopilot uses, into your local
REM Ollama. Nothing leaves your machine: Ollama runs locally and Spidy only
REM talks to http://127.0.0.1:11434. Safe to re-run; skips models you have.
REM
REM Usage:
REM   install-models.bat                 pull the default (reasonably sized) set
REM   install-models.bat --with-large    also pull the big mixtral guide (~26GB)
REM   install-models.bat dolphin-mistral llama3.1:8b   pull only what you name
REM ---------------------------------------------------------------------------
setlocal enabledelayedexpansion

where ollama >nul 2>&1
if errorlevel 1 (
  echo Ollama is not installed. Get it from https://ollama.com/download , then re-run this script.
  exit /b 1
)

ollama list >nul 2>&1
if errorlevel 1 (
  echo Could not reach Ollama. Start it first with:  ollama serve
  exit /b 1
)

REM Default set: name^|approx size^|note
set "DEFAULTS=dolphin-mistral;dolphin3:8b;llama3.1:8b"
set "LARGE=dolphin-mixtral:8x7b"

set "WITH_LARGE=0"
set "NAMED="
for %%A in (%*) do (
  if "%%A"=="--with-large" (set "WITH_LARGE=1") else (set "NAMED=!NAMED! %%A")
)

set "LIST="
if not "!NAMED!"=="" (
  set "LIST=!NAMED!"
) else (
  set "LIST=%DEFAULTS:;= %"
  if "!WITH_LARGE!"=="1" set "LIST=!LIST! %LARGE%"
)

echo Spidy local models - pulling into your Ollama:
for %%M in (!LIST!) do (
  ollama list | findstr /b /c:"%%M " >nul 2>&1
  if errorlevel 1 (
    echo.
    echo ^>^> %%M
    ollama pull %%M
  ) else (
    echo    skip: %%M ^(already installed^)
  )
)

echo.
if "!WITH_LARGE!"=="0" if "!NAMED!"=="" echo Tip: add --with-large to also pull dolphin-mixtral:8x7b ^(a much stronger guide, ~26GB^).
echo In Spidy, click the refresh button next to the model pickers, then choose your Executor and Guide.
endlocal
