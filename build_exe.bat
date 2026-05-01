@echo off
title Building NetGuard Toolkit

echo ========================================
echo   NetGuard Toolkit - Builder
echo ========================================
echo.

echo [1/4] Instalando PyInstaller...
pip install pyinstaller

echo.
echo [2/4] Instalando dependencias...
pip install -r requirements.txt

echo.
echo [3/4] Compilando a EXE...
pyinstaller --onefile --console ^
            --name "NetGuard_Toolkit" ^
            --icon=icon.ico ^
            --add-data "src;src" ^
            --hidden-import=psutil ^
            --hidden-import=colorama ^
            --hidden-import=ipaddress ^
            src/netguard.py

echo.
echo [4/4] Limpiando archivos temporales...
if exist "*.spec" del "*.spec"

echo.
echo ========================================
echo   ¡COMPLETADO!
echo   El EXE esta en la carpeta "dist"
echo ========================================
pause
