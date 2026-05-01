from scapy.all import ARP, Ether, srp, sniff, conf
import threading
import time
from colorama import Fore
import utils

class ARPDetector:
    def __init__(self):
        self.ip_mac_map = {}
        self.suspicious_activity = []
        self.detection_active = False
        self.detection_thread = None
        
    def get_network_range(self):
        """Obtiene el rango de red actual"""
        import socket
        import netifaces
        
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            ip = default_gateway[0]
            # Convertir a rango /24
            network = '.'.join(ip.split('.')[:-1]) + '.0/24'
            return network
        except:
            return "192.168.1.0/24"  # Default si no detecta
    
    def scan_network(self, network_range=None):
        """Escanea la red para construir mapa ARP inicial"""
        if not network_range:
            network_range = self.get_network_range()
        
        print(f"{Fore.CYAN}[*] Escaneando red: {network_range}")
        
        # Crear paquete ARP
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        # Enviar y recibir respuesta
        result = srp(packet, timeout=3, verbose=0)[0]
        
        # Construir mapa IP -> MAC
        for sent, received in result:
            self.ip_mac_map[received.psrc] = received.hwsrc
        
        print(f"{Fore.GREEN}[✓] {len(self.ip_mac_map)} dispositivos encontrados")
        return self.ip_mac_map
    
    def detect_arp_spoof(self, packet):
        """Analiza paquetes ARP en busca de spoofing"""
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP response
            ip_src = packet[ARP].psrc
            mac_src = packet[ARP].hwsrc
            
            # Si ya conocemos esta IP
            if ip_src in self.ip_mac_map:
                known_mac = self.ip_mac_map[ip_src]
                if known_mac != mac_src:
                    # Posible ARP spoofing
                    alert = {
                        'timestamp': time.time(),
                        'ip': ip_src,
                        'expected_mac': known_mac,
                        'detected_mac': mac_src,
                        'interface': packet.sniffed_on if hasattr(packet, 'sniffed_on') else 'unknown'
                    }
                    self.suspicious_activity.append(alert)
                    
                    print(f"{Fore.RED}[!] ¡POSIBLE ARP SPOOFING DETECTADO!")
                    print(f"    IP: {ip_src}")
                    print(f"    MAC esperada: {known_mac}")
                    print(f"    MAC detectada: {mac_src}")
                    
                    utils.log_activity(f"ARP Spoofing detectado - IP: {ip_src}")
            else:
                # Nueva IP detectada
                self.ip_mac_map[ip_src] = mac_src
                print(f"{Fore.GREEN}[+] Nuevo dispositivo: {ip_src} -> {mac_src}")
    
    def start_detection(self, interface=None):
        """Inicia la detección de ARP spoofing en tiempo real"""
        if self.detection_active:
            print(f"{Fore.YELLOW}[!] La detección ya está activa")
            return
        
        self.detection_active = True
        
        # Escanear red primero
        self.scan_network()
        
        print(f"{Fore.CYAN}[*] Iniciando monitoreo ARP (Ctrl+C para detener)")
        print(f"{Fore.YELLOW}[*] Escuchando en interfaz: {interface or 'todas'}")
        
        try:
            # Iniciar sniffing
            sniff(
                filter="arp",
                prn=self.detect_arp_spoof,
                store=0,
                timeout=None,
                iface=interface
            )
        except KeyboardInterrupt:
            self.stop_detection()
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
            self.stop_detection()
    
    def stop_detection(self):
        """Detiene la detección"""
        self.detection_active = False
        print(f"\n{Fore.YELLOW}[*] Monitoreo ARP detenido")
        
        # Mostrar resumen
        if self.suspicious_activity:
            print(f"{Fore.RED}[!] Se detectaron {len(self.suspicious_activity)} intentos de ARP spoofing")
        else:
            print(f"{Fore.GREEN}[✓] No se detectó actividad sospechosa ARP")
    
    def get_report(self):
        """Genera reporte de actividad ARP"""
        return {
            'total_devices': len(self.ip_mac_map),
            'suspicious_events': len(self.suspicious_activity),
            'events': self.suspicious_activity,
            'mac_table': self.ip_mac_map
        }

def monitor_arp():
    """Función principal para monitoreo ARP"""
    detector = ARPDetector()
    detector.start_detection()
