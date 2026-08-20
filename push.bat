@echo off
REM Push reconkg to github.com/xGhst0/reconkg from a short path.
REM
REM Why this exists: the Claude outputs folder sits under
REM   AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\...
REM which is ~250 characters before git appends .git\objects\ab\cdef...
REM Windows MAX_PATH is 260, so git cannot open its own loose objects and
REM the push dies with "Filename too long". core.longpaths=true fixes it
REM for most operations; this sidesteps it completely by working from C:\.
REM
REM Double-click, or run from a terminal. Safe to re-run.

setlocal
set DEST=C:\reconkg
set REMOTE=https://github.com/xGhst0/reconkg.git

echo.
echo === reconkg publish ===
echo.

where git >nul 2>&1
if errorlevel 1 (
    echo ERROR: git is not installed or not on PATH.
    echo Install it from https://git-scm.com/download/win
    goto :end
)

if exist "%DEST%" (
    echo %DEST% already exists.
    echo Delete it first if you want a clean copy, then re-run.
    echo.
    cd /d "%DEST%"
    goto :push
)

echo Copying the repository to %DEST% ...
robocopy "%~dp0." "%DEST%" /E /NFL /NDL /NJH /NJS /NP >nul
REM robocopy exit codes below 8 are success; 8+ is a real failure.
if errorlevel 8 (
    echo ERROR: copy failed.
    goto :end
)

cd /d "%DEST%"

echo Cleaning artefacts that should not be published ...
if exist reconkg.zip del /q reconkg.zip
if exist .pytest_cache rmdir /s /q .pytest_cache
if exist .hypothesis rmdir /s /q .hypothesis

echo.
git config core.longpaths true
git remote set-url origin %REMOTE% 2>nul || git remote add origin %REMOTE%
git branch -M main

:push
echo.
echo Repository state:
git log --oneline -1
for /f %%c in ('git ls-files ^| find /c /v ""') do echo   %%c files tracked
echo.
echo Pushing to %REMOTE%
echo.
echo   If prompted for a password, use a Personal Access Token, NOT your
echo   account password. GitHub stopped accepting passwords in 2021.
echo   Create one at https://github.com/settings/tokens with 'repo' scope.
echo.

git push -u origin main
if errorlevel 1 (
    echo.
    echo Push failed. Most likely causes:
    echo   - authentication: use a Personal Access Token as the password
    echo   - the remote already has commits: git pull --rebase origin main
    goto :end
)

echo.
echo === Done ===
echo.
echo   https://github.com/xGhst0/reconkg
echo.
echo   The working copy now lives at %DEST% -- push future changes from
echo   there rather than from the Claude outputs folder, which is too
echo   deep for git on Windows.
echo.

:end
endlocal
pause
