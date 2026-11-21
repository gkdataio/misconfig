@echo off
setlocal
node.exe -e "process.exit(Number(process.versions.node.split('.')[0]) >= 18 ? 0 : 1)" >nul 2>&1
if errorlevel 1 (
  echo This demo needs Node.js 18 or newer.
  pause
  exit /b 2
)
node.exe "%~dp0bin\misconfig.js" --demo
set "demoExit=%errorlevel%"
echo(
pause
exit /b %demoExit%
