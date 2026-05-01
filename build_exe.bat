@echo off
title NetGuard Toolkit - Builder v2.0

echo ========================================
echo   NetGuard Toolkit v2.0 - Builder
echo   Herramienta Completa de Seguridad
echo ========================================
echo.

echo [1/5] Instalando dependencias...
pip install --upgrade pip
pip install pyinstaller psutil colorama ipaddress scapy reportlab requests netifaces paramiko

echo.
echo [2/5] Verificando dependencias...
python -c "import psutil, colorama, scapy, reportlab, requests, netifaces, paramiko" 2>nul
if errorlevel 1 (
    echo [!] Error instalando dependencias
    pause
    exit /b
)

echo.
echo [3/5] Limpiando builds anteriores...
if exist "build" rmdir /s /q build
if exist "dist" rmdir /s /q dist
if exist "*.spec" del *.spec

echo.
echo [4/5] Compilando NetGuard Toolkit...
echo Esto puede tomar varios minutos...

pyinstaller --onefile --console ^
            --name "NetGuard_Toolkit_v2" ^
            --icon=icon.ico ^
            --add-data "src;src" ^
            --hidden-import=psutil ^
            --hidden-import=colorama ^
            --hidden-import=ipaddress ^
            --hidden-import=scapy ^
            --hidden-import=scapy.all ^
            --hidden-import=reportlab ^
            --hidden-import=requests ^
            --hidden-import=netifaces ^
            --hidden-import=paramiko ^
            --hidden-import=ssl ^
            --hidden-import=socket ^
            --hidden-import=threading ^
            --hidden-import=pickle ^
            --collect-all=scapy ^
            src/netguard.py

echo.
echo [5/5] Creando estructura de directorios...
if not exist "dist\reports" mkdir dist\reports

echo.
echo ========================================
echo   ¡COMPILACIÓN COMPLETADA!
echo ========================================
echo.
echo El ejecutable se encuentra en:
echo   dist\NetGuard_Toolkit_v2.exe
echo.
echo Reportes PDF se guardarán en:
echo   dist\reports\
echo.
echo Para ejecutar:
echo   1. Navega a la carpeta dist
echo   2. Ejecuta NetGuard_Toolkit_v2.exe como Administrador
echo.
pause
