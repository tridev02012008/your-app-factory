@echo off
setlocal
pushd "%~dp0" || exit /b 1
where npm.cmd >nul 2>&1
if errorlevel 1 goto neednode
node -e "require('node:sqlite')" >nul 2>&1
if errorlevel 1 goto neednode

if exist "node_modules\.package-lock.json" goto startapp
echo Pehli baar app ke packages install ho rahe hain...
call npm.cmd ci
if errorlevel 1 goto failed

:startapp
call npm.cmd start
if errorlevel 1 goto failed
popd
exit /b 0

:neednode
echo Node.js 24.x install karein. Phir is file ko dobara kholen.
goto stop

:failed
echo Upar diye message ko dekhein. Setup ke steps README-HI.md mein hain.
:stop
pause
popd
exit /b 1
