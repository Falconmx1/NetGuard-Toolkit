import os
import subprocess
from scanner import scan_ports
from monitor import monitor_traffic

def show_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
    ╔══════════════════════════════╗
    ║   NetGuard Toolkit v1.0      ║
    ║   Herramienta de Seguridad   ║
    ╚══════════════════════════════╝
    """)

def main_menu():
    while True:
        show_banner()
        print("1. Escaneo de puertos")
        print("2. Monitoreo de tráfico")
        print("3. Configurar firewall")
        print("4. Ver conexiones activas")
        print("5. Salir")
        
        choice = input("\n[+] Opción: ")
        
        if choice == '1':
            target = input("IP a escanear: ")
            scan_ports(target)
        elif choice == '2':
            monitor_traffic()
        elif choice == '3':
            os.system("wf.msc")  # Abre firewall de Windows
        elif choice == '4':
            os.system("netstat -an")
        elif choice == '5':
            break
        
        input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main_menu()
