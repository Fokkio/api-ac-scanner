@echo off
chcp 65001 >nul
setlocal

set "CONTROL_SCRIPT=%~dp0scripts\run.ps1"
if not exist "%CONTROL_SCRIPT%" (
  echo [!] Missing controller: %CONTROL_SCRIPT%
  echo [!] Keep the scripts folder next to run.bat.
  pause
  exit /b 1
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CONTROL_SCRIPT%" %*
set "CONTROL_EXIT=%ERRORLEVEL%"

if not "%CONTROL_EXIT%"=="0" (
  echo.
  echo [!] Local controller exited with code %CONTROL_EXIT%.
  pause
)

exit /b %CONTROL_EXIT%
