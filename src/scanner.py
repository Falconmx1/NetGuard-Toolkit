import socket
from datetime import datetime

def scan_ports(target, start_port=1, end_port=1024):
    print(f"\n[+] Escaneando {target} desde puerto {start_port} hasta {end_port}")
    start_time = datetime.now()
    
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"[✓] Puerto {port}: ABIERTO")
            open_ports.append(port)
        sock.close()
    
    end_time = datetime.now()
    print(f"\n[+] Escaneo completado en {end_time - start_time}")
    return open_ports
