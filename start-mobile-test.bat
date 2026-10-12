@echo off
setlocal
rem Run the supervisor in its own visible PowerShell window.  This prevents
rem cmd.exe from showing its "Terminate batch job" prompt when Ctrl+C is used
rem to stop the mobile-testing session.
start "SecureVote mobile test" /wait powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\start-mobile-test.ps1"
endlocal
