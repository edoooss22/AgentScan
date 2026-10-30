@echo off
setlocal
cd /d "%~dp0"

if not exist dist mkdir dist

echo [1/2] Full self-contained build...
dotnet publish src -c Release -o obj\publish-full
if errorlevel 1 goto failed
copy /y obj\publish-full\AgentScan.exe dist\AgentScan.exe >nul

echo.
echo [2/2] Lite framework-dependent build (.NET 8 Desktop Runtime required)...
dotnet publish src -c Release -o obj\publish-lite -p:SelfContained=false -p:EnableCompressionInSingleFile=false -p:PublishReadyToRun=false
if errorlevel 1 goto failed
copy /y obj\publish-lite\AgentScan.exe dist\AgentScan-lite.exe >nul

echo.
for %%F in (dist\AgentScan.exe) do echo Full: %%~fF  %%~zF bytes
for %%F in (dist\AgentScan-lite.exe) do echo Lite: %%~fF  %%~zF bytes
echo.
echo Usage on the machine being checked (run as administrator):
echo   AgentScan.exe                 - window: pick process, progress, report buttons
echo   AgentScan.exe --pid 1234      - console mode, explicit PID
echo   AgentScan.exe --console       - console mode, find Minecraft automatically
endlocal
exit /b 0

:failed
echo.
echo BUILD FAILED. Check .NET SDK 8.0: dotnet --version
endlocal
exit /b 1
