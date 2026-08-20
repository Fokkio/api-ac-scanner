@echo off
chcp 65001 >nul
title API AC Scanner - Docker Control
setlocal enabledelayedexpansion

cd /d "%~dp0" || (
  echo [!] Cannot find project folder. Put this .bat next to docker-compose.yml.
  pause & exit /b 1
)

:menu
cls
echo ============================================
echo        API Access-Control Scanner - Docker
echo ============================================
echo.
echo   1) Build    - build scanner + web images
echo   2) Start    - docker compose up -d  (run stack)
echo   3) Rebuild  - build --no-cache web then up (after editing code)
echo   4) Stop     - docker compose down (remove containers)
echo   5) Status   - docker compose ps
echo   6) Logs     - tail web + scanner logs
echo   7) Open     - open http://localhost:3000 in browser
echo   8) Exit
echo.
set /p "choice=Select (1-8): "

if "%choice%"=="1" goto build
if "%choice%"=="2" goto start
if "%choice%"=="3" goto rebuild
if "%choice%"=="4" goto stop
if "%choice%"=="5" goto status
if "%choice%"=="6" goto logs
if "%choice%"=="7" goto open
if "%choice%"=="8" exit /b 0
goto menu

:build
echo [*] Building images...
docker compose build
echo [+] Build done. Press any key to return.
pause >nul
goto menu

:start
echo [*] Starting stack...
docker compose up -d
echo [+] Started. Open http://localhost:3000
pause >nul
goto menu

:rebuild
echo [*] Rebuilding web (no-cache) + starting...
docker compose build --no-cache web
docker compose up -d --force-recreate
echo [+] Done.
pause >nul
goto menu

:stop
echo [*] Stopping stack...
docker compose down
echo [+] Stopped.
pause >nul
goto menu

:status
docker compose ps
pause >nul
goto menu

:logs
docker compose logs --tail 30 web scanner
pause >nul
goto menu

:open
start "" http://localhost:3000
goto menu
