import socket
import threading
from datetime import datetime
from colorama import init, Fore, Style
import ipaddress

init(autoreset=True)

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024, threads=100):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.open_ports = []
        self.lock = threading.Lock()
        
    def get_service_name(self, port):
        """Obtiene nombre del servicio por puerto"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC",
            135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt"
        }
        return common_ports.get(port, "Desconocido")
    
    def scan_port(self, port):
        """Escanea un puerto individual"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = self.get_service_name(port)
                with self.lock:
                    self.open_ports.append(port)
                    print(f"{Fore.GREEN}[+] Puerto {port}: ABIERTO - {service}")
                    log_activity(f"Puerto abierto: {port} - {service} en {self.target}")
            sock.close()
        except Exception as e:
            pass
    
    def scan(self):
        """Ejecuta el escaneo multi-thread"""
        print(f"{Fore.CYAN}[*] Iniciando escaneo en {self.target}")
        print(f"[*] Rango: {self.start_port}-{self.end_port}")
        print(f"[*] Usando {self.threads} hilos")
        print("-" * 50)
        
        start_time = datetime.now()
        
        # Crear y ejecutar hilos
        threads_list = []
        ports_per_thread = (self.end_port - self.start_port + 1) // self.threads
        
        for i in range(self.threads):
            start = self.start_port + i * ports_per_thread
            end = start + ports_per_thread if i < self.threads - 1 else self.end_port
            
            def scan_range(s, e):
                for port in range(s, e + 1):
                    self.scan_port(port)
            
            thread = threading.Thread(target=scan_range, args=(start, end))
            threads_list.append(thread)
            thread.start()
        
        # Esperar a que terminen
        for thread in threads_list:
            thread.join()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        print("-" * 50)
        print(f"{Fore.CYAN}[*] Escaneo completado en {duration}")
        print(f"{Fore.YELLOW}[*] Puertos abiertos encontrados: {len(self.open_ports)}")
        
        if self.open_ports:
            print(f"{Fore.GREEN}[+] Lista de puertos abiertos:")
            for port in sorted(self.open_ports):
                print(f"    - {port}: {self.get_service_name(port)}")
        
        return self.open_ports

def quick_scan(ip):
    """Escaneo rápido de puertos comunes"""
    scanner = PortScanner(ip, 1, 1000, 50)
    return scanner.scan()

def full_scan(ip):
    """Escaneo completo (1-65535)"""
    scanner = PortScanner(ip, 1, 65535, 200)
    return scanner.scan()

def scan_network(network):
    """Escanea toda una red"""
    print(f"{Fore.CYAN}[*] Escaneando red: {network}")
    active_hosts = []
    
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        for ip in network_obj.hosts():
            ip_str = str(ip)
            response = os.system(f"ping -n 1 -w 1000 {ip_str} > nul 2>&1")
            if response == 0:
                print(f"{Fore.GREEN}[✓] Host activo: {ip_str}")
                active_hosts.append(ip_str)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}")
    
    return active_hosts
