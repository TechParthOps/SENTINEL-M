@echo off
setlocal EnableDelayedExpansion
rem ===========================================================================
rem  SENTINEL-M auto-updater (companion of start.bat --auto-update)
rem  Polls git pull; when the code changes, uvicorn --reload and the Vite dev
rem  server pick it up automatically. Reinstalls dependencies only when
rem  requirements.txt / package.json actually changed.
rem
rem    scripts\auto_update.bat [repo-root] [interval-seconds]
rem ===========================================================================

set "ROOT=%~1"
if "%ROOT%"=="" set "ROOT=%CD%"
set "INTERVAL=%~2"
if "%INTERVAL%"=="" set "INTERVAL=300"
set "LAST=%TEMP%\sentinel-autoupdate-rev.txt"
set "PYEXE=%ROOT%\backend\.venv\Scripts\python.exe"

echo SENTINEL-M auto-updater: "%ROOT%" every %INTERVAL%s. Press Ctrl+C to stop.
if not exist "%ROOT%\.git" (echo [ERROR] not a git repository - auto-update needs git. & exit /b 1)

git -C "%ROOT%" remote | findstr . >nul
if errorlevel 1 (
    echo [note] No git remote configured - nothing to pull.
    echo [note] Add one with:  git remote add origin ^<your-repo-url^>
    echo [note] The loop keeps running; local commits are still detected below.
)

:loop
git -C "%ROOT%" pull --ff-only --quiet
if errorlevel 1 (
    echo [warn] git pull failed - retrying in %INTERVAL%s
    timeout /t %INTERVAL% /nobreak >nul
    goto loop
)
for /f "delims=" %%r in ('git -C "%ROOT%" rev-parse HEAD') do set "NOW=%%r"
set "PREV="
if exist "%LAST%" set /p PREV=<"%LAST%"

if defined PREV if not "!PREV!"=="!NOW!" (
    echo [update] code changed !PREV:~0,8! -^> !NOW:~0,8!
    git -C "%ROOT%" diff --name-only !PREV! !NOW! | findstr /i /c:"requirements.txt" >nul && (
        echo [update] reinstalling backend dependencies...
        if exist "!PYEXE!" "!PYEXE!" -m pip install --quiet --disable-pip-version-check -r "%ROOT%\backend\requirements.txt"
    )
    git -C "%ROOT%" diff --name-only !PREV! !NOW! | findstr /i /c:"package.json" >nul && (
        echo [update] reinstalling frontend dependencies...
        cd /d "%ROOT%\frontend" && call npm install --silent
    )
    echo [update] applied. Reloading servers is automatic ^(uvicorn --reload / Vite HMR^).
)

echo !NOW!>"%LAST%"
timeout /t %INTERVAL% /nobreak >nul
goto loop