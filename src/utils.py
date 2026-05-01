import os
import sys
import platform
import subprocess
from datetime import datetime
import ctypes

def is_admin():
    """Verifica si el script se ejecuta como administrador"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Re-ejecuta el script como administrador"""
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()

def clear_screen():
    """Limpia la pantalla según el SO"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def print_header(title):
    """Imprime un header bonito"""
    clear_screen()
    print("=" * 60)
    print(f"  NetGuard Toolkit - {title}")
    print("=" * 60)
    print()

def log_activity(message, log_file="netguard.log"):
    """Guarda actividades en un log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] {message}\n")
