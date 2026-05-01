import socket
import threading
import json
import pickle
from datetime import datetime
from colorama import Fore
import utils
from port_scanner import PortScanner
from network_monitor import get_connections, get_bandwidth

class NetGuardServer:
    def __init__(self, host='0.0.0.0', port=9999, password='admin123'):
        self.host = host
        self.port = port
        self.password = password
        self.server_socket = None
        self.clients = []
        self.running = False
        
    def authenticate(self, client_socket):
        """Autentica al cliente"""
        try:
            client_socket.send(b"AUTH_REQUIRED")
            password = client_socket.recv(1024).decode()
            
            if password == self.password:
                client_socket.send(b"AUTH_SUCCESS")
                return True
            else:
                client_socket.send(b"AUTH_FAILED")
                return False
        except:
            return False
    
    def handle_client(self, client_socket, address):
        """Maneja comandos del cliente"""
        print(f"{Fore.GREEN}[+] Cliente conectado: {address}")
        
        # Autenticar
        if not self.authenticate(client_socket):
            print(f"{Fore.RED}[-] Autenticación fallida: {address}")
            client_socket.close()
            return
        
        utils.log_activity(f"Cliente remoto conectado: {address}")
        
        while self.running:
            try:
                # Recibir comando
                command = client_socket.recv(1024).decode()
                
                if not command:
                    break
                
                print(f"{Fore.CYAN}[*] Comando recibido de {address}: {command}")
                
                # Procesar comandos
                response = self.process_command(command)
                
                # Enviar respuesta
                client_socket.send(pickle.dumps(response))
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error con cliente {address}: {e}")
                break
        
        client_socket.close()
        print(f"{Fore.YELLOW}[-] Cliente desconectado: {address}")
    
    def process_command(self, command):
        """Procesa comandos del cliente"""
        try:
            cmd_parts = command.split()
            cmd = cmd_parts[0].lower()
            
            if cmd == "scan":
                # Escaneo de puertos
                target = cmd_parts[1] if len(cmd_parts) > 1 else "localhost"
                scanner = PortScanner(target, 1, 1024, 50)
                open_ports = scanner.scan()
                return {
                    'status': 'success',
                    'command': 'scan',
                    'data': open_ports,
                    'target': target
                }
            
            elif cmd == "connections":
                # Conexiones activas
                connections = get_connections()
                return {
                    'status': 'success',
                    'command': 'connections',
                    'data': connections[:50]
                }
            
            elif cmd == "bandwidth":
                # Ancho de banda
                sent, recv = get_bandwidth()
                return {
                    'status': 'success',
                    'command': 'bandwidth',
                    'data': {
                        'upload_kbps': sent,
                        'download_kbps': recv
                    }
                }
            
            elif cmd == "info":
                # Información del sistema
                import platform
                import psutil
                
                info = {
                    'hostname': socket.gethostname(),
                    'os': platform.system() + " " + platform.release(),
                    'cpu_percent': psutil.cpu_percent(),
                    'memory_percent': psutil.virtual_memory().percent,
                    'timestamp': datetime.now().isoformat()
                }
                return {
                    'status': 'success',
                    'command': 'info',
                    'data': info
                }
            
            elif cmd == "block_ip":
                # Bloquear IP (requiere firewall)
                if len(cmd_parts) > 1:
                    ip = cmd_parts[1]
                    from firewall_manager import FirewallManager
                    fw = FirewallManager()
                    result = fw.block_ip(ip)
                    return {
                        'status': 'success' if result else 'error',
                        'command': 'block_ip',
                        'data': {'ip': ip, 'blocked': result}
                    }
            
            elif cmd == "help":
                return {
                    'status': 'success',
                    'command': 'help',
                    'data': {
                        'commands': [
                            'scan <ip> - Escanear puertos',
                            'connections - Ver conexiones activas',
                            'bandwidth - Ver ancho de banda',
                            'info - Información del sistema',
                            'block_ip <ip> - Bloquear IP',
                            'exit - Desconectar'
                        ]
                    }
                }
            
            else:
                return {
                    'status': 'error',
                    'command': command,
                    'data': f"Comando desconocido: {command}"
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'command': command,
                'data': str(e)
            }
    
    def start(self):
        """Inicia el servidor"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            self.running = True
            
            print(f"{Fore.GREEN}")
            print("╔══════════════════════════════════════╗")
            print("║   NetGuard Remote Server v1.0        ║")
            print("║   Modo de monitoreo remoto           ║")
            print("╚══════════════════════════════════════╝")
            print(f"{Fore.CYAN}")
            print(f"[*] Servidor corriendo en {self.host}:{self.port}")
            print(f"[*] Contraseña: {self.password}")
            print(f"[*] Esperando conexiones...")
            
            utils.log_activity(f"Servidor remoto iniciado en puerto {self.port}")
            
            while self.running:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                self.clients.append(client_thread)
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Deteniendo servidor...")
            self.stop()
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
    
    def stop(self):
        """Detiene el servidor"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        print(f"{Fore.GREEN}[✓] Servidor detenido")

class NetGuardClient:
    """Cliente para conectarse al servidor remoto"""
    
    def __init__(self, server_ip, port=9999, password='admin123'):
        self.server_ip = server_ip
        self.port = port
        self.password = password
        self.socket = None
    
    def connect(self):
        """Conecta al servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.port))
            
            # Autenticación
            response = self.socket.recv(1024).decode()
            if response == "AUTH_REQUIRED":
                self.socket.send(self.password.encode())
                auth_response = self.socket.recv(1024).decode()
                
                if auth_response == "AUTH_SUCCESS":
                    print(f"{Fore.GREEN}[✓] Conectado al servidor {self.server_ip}:{self.port}")
                    return True
                else:
                    print(f"{Fore.RED}[!] Autenticación fallida")
                    return False
            else:
                print(f"{Fore.RED}[!] Error de protocolo")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[!] Error de conexión: {e}")
            return False
    
    def send_command(self, command):
        """Envía comando al servidor"""
        try:
            self.socket.send(command.encode())
            response = pickle.loads(self.socket.recv(4096))
            return response
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
            return None
    
    def interactive_mode(self):
        """Modo interactivo del cliente"""
        if not self.connect():
            return
        
        print(f"{Fore.CYAN}[*] Modo interactivo iniciado")
        print("Escribe 'help' para ver comandos, 'exit' para salir\n")
        
        while True:
            cmd = input(f"{Fore.GREEN}NetGuard> {Fore.WHITE}")
            
            if cmd.lower() == 'exit':
                break
            
            response = self.send_command(cmd)
            
            if response:
                if response['status'] == 'success':
                    print(f"{Fore.GREEN}[+] Respuesta:")
                    import pprint
                    pprint.pprint(response['data'])
                else:
                    print(f"{Fore.RED}[!] Error: {response['data']}")
            else:
                print(f"{Fore.RED}[!] No se recibió respuesta")
        
        self.socket.close()
        print(f"{Fore.YELLOW}[*] Desconectado")
