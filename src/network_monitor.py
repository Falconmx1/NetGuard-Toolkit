import psutil
import time
from datetime import datetime
from colorama import Fore
import socket

def get_connections():
    """Obtiene conexiones activas"""
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'ESTABLISHED':
            connections.append({
                'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                'status': conn.status,
                'pid': conn.pid
            })
    return connections

def monitor_connections(interval=2):
    """Monitorea conexiones en tiempo real"""
    print(f"{Fore.CYAN}[*] Monitoreando conexiones activas (Ctrl+C para detener)")
    print("-" * 80)
    
    try:
        while True:
            connections = get_connections()
            print(f"\n{Fore.YELLOW}[{datetime.now().strftime('%H:%M:%S')}] Conexiones activas: {len(connections)}")
            print(f"{Fore.CYAN}LOCAL                    REMOTE                   STATUS")
            print("-" * 80)
            
            for conn in connections[:20]:  # Mostrar solo 20
                print(f"{Fore.WHITE}{conn['local']:<23} {conn['remote']:<23} {conn['status']}")
            
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Monitoreo detenido")

def get_bandwidth():
    """Obtiene uso de ancho de banda"""
    old_sent = psutil.net_io_counters().bytes_sent
    old_recv = psutil.net_io_counters().bytes_recv
    
    time.sleep(1)
    
    new_sent = psutil.net_io_counters().bytes_sent
    new_recv = psutil.net_io_counters().bytes_recv
    
    sent_speed = (new_sent - old_sent) / 1024  # KB/s
    recv_speed = (new_recv - old_recv) / 1024  # KB/s
    
    return sent_speed, recv_speed

def show_network_info():
    """Muestra información de la red"""
    print(f"{Fore.CYAN}[*] Información de red:")
    
    # Interfaces de red
    interfaces = psutil.net_if_addrs()
    for interface, addrs in interfaces.items():
        print(f"\n  {Fore.GREEN}{interface}:")
        for addr in addrs:
            if addr.family == socket.AF_INET:
                print(f"    IPv4: {addr.address}")
            elif addr.family == socket.AF_INET6:
                print(f"    IPv6: {addr.address}")
    
    # Estadísticas
    stats = psutil.net_if_stats()
    print(f"\n{Fore.CYAN}[*] Estado de interfaces:")
    for interface, stat in stats.items():
        status = "UP" if stat.isup else "DOWN"
        print(f"  {interface}: {status} - {stat.speed} Mbps")
    
    # Conexiones por puerto
    connections = get_connections()
    ports = {}
    for conn in connections:
        local_port = conn['local'].split(':')[-1] if ':' in conn['local'] else None
        if local_port and local_port.isdigit():
            ports[local_port] = ports.get(local_port, 0) + 1
    
    print(f"\n{Fore.CYAN}[*] Puertos locales más usados:")
    for port, count in sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  Puerto {port}: {count} conexiones")
