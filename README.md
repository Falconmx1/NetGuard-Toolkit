# 🛡️ NetGuard Toolkit

**Herramienta de seguridad de red fácil de usar para Windows**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

## ✨ Características
- 🔍 Escaneo rápido de puertos
- 📊 Monitoreo de tráfico en tiempo real
- 🧱 Gestión simplificada del firewall de Windows
- 📡 Visualización de conexiones activas

## 🚀 Instalación

```bash
git clone https://github.com/Falconmx1/NetGuard-Toolkit.git
cd NetGuard-Toolkit
pip install -r requirements.txt
python src/netguard.py

🎯 Uso básico

Ejecuta el script y sigue el menú interactivo. Requiere permisos de administrador para funciones avanzadas.
📦 Compilar a .exe
bash

pip install pyinstaller
pyinstaller --onefile --console src/netguard.py

🚀 Pasos para generar el EXE funcional

1. Instalación inicial
# Clona o crea la carpeta del proyecto
mkdir NetGuard-Toolkit
cd NetGuard-Toolkit

# Crea la estructura de carpetas
mkdir src

# Copia todos los archivos .py en src/
# Copia requirements.txt y build_exe.bat en la raíz

2. Ejecuta el builder
# Desde la carpeta raíz del proyecto
build_exe.bat

# O manualmente:
pip install pyinstaller psutil colorama ipaddress
pyinstaller --onefile --console --name "NetGuard_Toolkit" src/netguard.py

3. El EXE estará en:
NetGuard-Toolkit/dist/NetGuard_Toolkit.exe
