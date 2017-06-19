@echo off

set /p OSLib3_GENERATOR=<%OSLib3_DIR%/OSLibGenerator.txt 
IF %ERRORLEVEL% NEQ 0 PAUSE

echo Automatically making project with the same CMake generator (%OSLib3_GENERATOR%) as used to make the OSLib in '%OSLib3_DIR%'

if not exist build mkdir build 
cd build

cmake -G "%OSLib3_GENERATOR%"  ../
IF %ERRORLEVEL% NEQ 0 PAUSE

cd ..
