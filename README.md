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

📋 Instrucciones finales

1. Instalación desde cero:
# Clonar o crear proyecto
mkdir NetGuard-Toolkit
cd NetGuard-Toolkit

# Crear estructura
mkdir src
mkdir reports

# Copiar todos los archivos .py en src/
# Copiar requirements.txt y build_exe.bat en raíz

# Ejecutar builder
build_exe.bat

2. Características completas:

✅ Escáner de vulnerabilidades

    SSL/TLS inseguros

    Puertos vulnerables

    Credenciales por defecto

    Headers HTTP faltantes

✅ Detección ARP Spoofing

    Monitoreo en tiempo real

    Detección de MITM

    Reporte detallado

✅ Modo servidor remoto

    Comandos: scan, connections, bandwidth, info, block_ip

    Autenticación por contraseña

    Múltiples clientes simultáneos

✅ Generador PDF

    Reportes profesionales

    Tablas de resultados

    Recomendaciones de seguridad

    Análisis de vulnerabilidades

3. Uso del servidor remoto:

Servidor (Windows a monitorear):
NetGuard_Toolkit_v2.exe
# Opción 6 -> 1 -> Puerto 9999 -> Contraseña

Cliente (desde otra máquina):
NetGuard_Toolkit_v2.exe
# Opción 6 -> 2 -> IP del servidor -> Puerto 9999 -> Contraseña
# Comandos disponibles: help, scan 192.168.1.1, connections, etc.
4. Reporte PDF generado incluye:

    Fecha y hora del análisis

    Puertos abiertos y servicios

    Vulnerabilidades encontradas con nivel de riesgo

    Análisis ARP (si aplica)

    Dispositivos en la red

    Recomendaciones de seguridad personalizadas
