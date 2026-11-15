@echo off
setlocal EnableDelayedExpansion
rem ===========================================================================
rem  SENTINEL-M one-click starter
rem
rem    start.bat                 start backend (auto-reload) + frontend (HMR)
rem    start.bat --update        pull latest code first, then start
rem    start.bat --auto-update   start + keep polling git every 5 minutes;
rem                               changed code is picked up automatically by
rem                               uvicorn --reload and the Vite dev server
rem    start.bat --stop          stop all SENTINEL-M servers on the ports
rem ===========================================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "BACKEND=%ROOT%\backend"
set "FRONTEND=%ROOT%\frontend"
set "PYEXE=%BACKEND%\.venv\Scripts\python.exe"
if defined SENTINEL_PORT (set "PORT=%SENTINEL_PORT%") else (set "PORT=8942")

rem ---------------------------------------------------------------- arguments
set "MODE=start"
if /i "%~1"=="--update"      set "MODE=update"
if /i "%~1"=="--auto-update" set "MODE=auto-update"
if /i "%~1"=="--stop"        set "MODE=stop"

rem --------------------------------------------------------------- stop mode
if "%MODE%"=="stop" (
    echo Stopping SENTINEL-M servers on ports %PORT% and 5173...
    rem uvicorn --reload respawns its worker, so kill the process tree by command line
    powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*uvicorn*app.main:app*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" 2>nul
    powershell -NoProfile -Command "foreach ($p in @('%PORT%','5173')) { try { Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction Stop | Select-Object -Expand OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force } } catch {} }"
    powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" | Where-Object { $_.CommandLine -like '*vite*' -and $_.CommandLine -like '*SENTINEL*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" 2>nul
    taskkill /fi "WINDOWTITLE eq SENTINEL-M Auto-Update*" /t /f >nul 2>&1
    echo Done.
    exit /b 0
)

echo ============================================================
echo   SENTINEL-M - Autonomous Cyber Defense Platform
echo ============================================================

rem ------------------------------------------------------------ prerequisites
where python >nul 2>&1 || (echo [ERROR] Python not found on PATH. Install Python 3.11+ and retry. & exit /b 1)
where npm    >nul 2>&1 || echo [WARN ] npm not found on PATH - the frontend cannot start.

if not exist "%PYEXE%" (
    echo [1/4] Creating backend virtual environment...
    python -m venv "%BACKEND%\.venv" || (echo [ERROR] could not create the virtual environment. & exit /b 1)
)
if not exist "%BACKEND%\.venv\Lib\site-packages\fastapi" (
    echo [1/4] Installing backend dependencies...
    "%PYEXE%" -m pip install --quiet --disable-pip-version-check -r "%BACKEND%\requirements.txt" || (echo [ERROR] backend dependency install failed. & exit /b 1)
)
if not exist "%FRONTEND%\node_modules" (
    echo [1/4] Installing frontend dependencies...
    pushd "%FRONTEND%" && call npm install --silent && popd || (echo [ERROR] npm install failed. & exit /b 1)
)
if not exist "%BACKEND%\.env" (
    if exist "%BACKEND%\.env.example" (
        echo [1/4] No backend\.env found - copying .env.example. Edit it to set SECRET_KEY.
        copy /y "%BACKEND%\.env.example" "%BACKEND%\.env" >nul
    ) else (
        echo [WARN ] No backend\.env found - a random secret is used for this session only.
    )
)

rem ------------------------------------------------------------ code update
if "%MODE%"=="update"   goto pull_once
if "%MODE%"=="auto-update" goto start_servers
goto start_servers

:pull_once
echo [2/4] Updating code from git...
if exist "%ROOT%\.git" (
    git -C "%ROOT%" pull --ff-only || echo [WARN ] git pull failed - continuing with the local code.
    rem keep dependencies in sync when requirements changed
    "%PYEXE%" -m pip install --quiet --disable-pip-version-check -r "%BACKEND%\requirements.txt"
    pushd "%FRONTEND%" && call npm install --silent && popd
) else echo [WARN ] no git repository - nothing to pull.
goto start_servers

rem ------------------------------------------------------------- start both
:start_servers
rem Windows can keep a killed listener's socket for a while - pick a free port
for /f "usebackq tokens=*" %%p in (`powershell -NoProfile -Command "$p=%PORT%; while (Get-NetTCPConnection -LocalPort $p -ErrorAction SilentlyContinue) { $p++ }; $p"`) do set "PORT=%%p"
echo [3/4] Starting backend on http://127.0.0.1:%PORT%  (auto-reload on Python changes)
start "SENTINEL-M Backend" cmd /k "cd /d "%BACKEND%" && "%PYEXE%" -m uvicorn app.main:app --reload --port %PORT%"

echo [3/4] Starting frontend on http://localhost:5173   (hot reload on file changes)
set "VITE_API_TARGET=http://127.0.0.1:%PORT%"
set "VITE_WS_TARGET=ws://127.0.0.1:%PORT%"
start "SENTINEL-M Frontend" cmd /k "cd /d "%FRONTEND%" && set VITE_API_TARGET=%VITE_API_TARGET% && set VITE_WS_TARGET=%VITE_WS_TARGET% && npm run dev"

echo [4/4] Open http://localhost:5173 and sign in.
echo.
echo     Backend logs : "SENTINEL-M Backend" window
echo     Frontend logs: "SENTINEL-M Frontend" window
echo     Stop servers : start.bat --stop
echo.

if "%MODE%"=="auto-update" (
    echo Auto-update armed: polling git every 300 seconds.
    start "SENTINEL-M Auto-Update" cmd /k ""%ROOT%\scripts\auto_update.bat" "%ROOT%" 300"
    echo The updater window pulls changes; uvicorn --reload and Vite HMR apply them live.
)

echo Done. Keep the new windows open to run the platform.
exit /b 0