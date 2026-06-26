@echo off
setlocal enabledelayedexpansion
cd /d %~dp0

if not exist build mkdir build
pushd build
cmake -G "Visual Studio 17 2022" -A x64 ..
if errorlevel 1 ( popd & echo [!] CMake configure failed & exit /b 1 )
cmake --build . --config Release --target GHaxSkyrimDumper -- /m /v:m
if errorlevel 1 ( popd & echo [!] Build failed & exit /b 2 )
popd

echo.
echo [+] Built: %~dp0build\Release\GHaxSkyrimDumper.exe
endlocal
