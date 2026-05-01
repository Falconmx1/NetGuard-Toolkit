import sys
import os
from colorama import init, Fore, Style
import utils
from port_scanner import PortScanner, scan_network, quick_scan, full_scan
from firewall_manager import FirewallManager
from network_monitor import monitor_connections, show_network_info, get_bandwidth

init(autoreset=True)

def banner():
    print(f"""{Fore.CYAN}
    ╔══════════════════════════════════════════════════╗
    ║  {Fore.WHITE}███╗   ██╗███████╗████████╗{Fore.CYAN}                    ║
    ║  {Fore.WHITE}████╗  ██║██╔════╝╚══██╔══╝{Fore.CYAN}                    ║
    ║  {Fore.WHITE}██╔██╗ ██║█████╗     ██║   {Fore.CYAN}                    ║
    ║  {Fore.WHITE}██║╚██╗██║██╔══╝     ██║   {Fore.CYAN}                    ║
    ║  {Fore.WHITE}██║ ╚████║███████╗   ██║   {Fore.CYAN}                    ║
    ║  {Fore.WHITE}╚═╝  ╚═══╝╚══════╝   ╚═╝   {Fore.CYAN}                    ║
    ║                                          {Fore.YELLOW}v1.0{Fore.CYAN}    ║
    ║        {Fore.GREEN}NetGuard Toolkit - Seguridad de Red{Fore.CYAN}        ║
    ╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
    """)

def port_scanner_menu():
    while True:
        utils.print_header("ESCÁNER DE PUERTOS")
        print("1. Escaneo rápido (puertos comunes)")
        print("2. Escaneo completo (1-65535)")
        print("3. Escanear red completa")
        print("4. Escaneo personalizado")
        print("5. Volver al menú principal")
        
        choice = input("\n[+] Opción: ")
        
        if choice == '1':
            target = input("IP objetivo: ")
            quick_scan(target)
        elif choice == '2':
            target = input("IP objetivo: ")
            print(f"{Fore.YELLOW}[!] Esto puede tomar varios minutos...")
            full_scan(target)
        elif choice == '3':
            network = input("Red (ej: 192.168.1.0/24): ")
            active = scan_network(network)
            print(f"\n{Fore.GREEN}[✓] Hosts encontrados: {len(active)}")
        elif choice == '4':
            target = input("IP objetivo: ")
            start = int(input("Puerto inicial: "))
            end = int(input("Puerto final: "))
            threads = int(input("Número de hilos (default 100): ") or 100)
            scanner = PortScanner(target, start, end, threads)
            scanner.scan()
        elif choice == '5':
            break
        
        input("\nPresiona Enter para continuar...")

def firewall_menu():
    fw = FirewallManager()
    
    while True:
        utils.print_header("GESTOR DE FIREWALL")
        print("1. Listar reglas actuales")
        print("2. Añadir regla (permitir puerto)")
        print("3. Bloquear puerto")
        print("4. Eliminar regla")
        print("5. Bloquear IP")
        print("6. Activar firewall")
        print("7. Desactivar firewall (PELIGROSO)")
        print("8. Volver al menú principal")
        
        choice = input("\n[+] Opción: ")
        
        if choice == '1':
            fw.list_rules()
        elif choice == '2':
            name = input("Nombre de la regla: ")
            port = input("Puerto: ")
            protocol = input("Protocolo (TCP/UDP): ").upper()
            fw.add_rule(name, port, protocol, "allow")
        elif choice == '3':
            name = input("Nombre de la regla: ")
            port = input("Puerto: ")
            protocol = input("Protocolo (TCP/UDP): ").upper()
            fw.add_rule(name, port, protocol, "block")
        elif choice == '4':
            name = input("Nombre de la regla a eliminar: ")
            fw.delete_rule(name)
        elif choice == '5':
            ip = input("IP a bloquear: ")
            fw.block_ip(ip)
        elif choice == '6':
            fw.enable_firewall()
        elif choice == '7':
            fw.disable_firewall()
        elif choice == '8':
            break
        
        input("\nPresiona Enter para continuar...")

def monitor_menu():
    while True:
        utils.print_header("MONITOR DE RED")
        print("1. Ver conexiones activas (tiempo real)")
        print("2. Información de red")
        print("3. Ver ancho de banda")
        print("4. Volver al menú principal")
        
        choice = input("\n[+] Opción: ")
        
        if choice == '1':
            monitor_connections()
        elif choice == '2':
            show_network_info()
        elif choice == '3':
            sent, recv = get_bandwidth()
            print(f"{Fore.GREEN}Subida: {sent:.2f} KB/s")
            print(f"Descarga: {recv:.2f} KB/s")
        elif choice == '4':
            break
        
        input("\nPresiona Enter para continuar...")

def main():
    # Verificar administrador
    if not utils.is_admin():
        print(f"{Fore.YELLOW}[!] No tienes permisos de administrador")
        print("[!] Algunas funciones no estarán disponibles")
        print("[!] Se recomienda ejecutar como administrador\n")
    
    while True:
        banner()
        print(f"{Fore.WHITE}1. {Fore.GREEN}Escáner de Puertos")
        print(f"{Fore.WHITE}2. {Fore.BLUE}Gestión de Firewall")
        print(f"{Fore.WHITE}3. {Fore.MAGENTA}Monitor de Red")
        print(f"{Fore.WHITE}4. {Fore.YELLOW}Acerca de")
        print(f"{Fore.WHITE}5. {Fore.RED}Salir")
        
        choice = input(f"\n{Fore.CYAN}[NetGuard] Selecciona una opción: {Fore.WHITE}")
        
        if choice == '1':
            port_scanner_menu()
        elif choice == '2':
            firewall_menu()
        elif choice == '3':
            monitor_menu()
        elif choice == '4':
            utils.print_header("ACERCA DE")
            print("NetGuard Toolkit v1.0")
            print("Herramienta educativa de seguridad de red")
            print("\nDesarrollada para Windows")
            print("Uso responsable y solo en redes autorizadas")
            input("\nPresiona Enter para continuar...")
        elif choice == '5':
            print(f"\n{Fore.GREEN}[✓] ¡Hasta luego!")
            utils.log_activity("Herramienta cerrada")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupción detectada. Saliendo...")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error fatal: {e}")
        input("Presiona Enter para salir...")
