#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NetGuard Toolkit v2.0 - Herramienta Completa de Seguridad de Red
Autor: NetGuard Team
Descripción: Suite de seguridad con escáner de puertos, firewall, monitoreo,
             detector ARP, vulnerabilidades, modo remoto y reportes PDF
"""

import sys
import os
import time
import socket
import threading
import subprocess
from datetime import datetime
from colorama import init, Fore, Style

# Importar módulos internos
import utils
from port_scanner import PortScanner, scan_network, quick_scan, full_scan
from firewall_manager import FirewallManager
from network_monitor import monitor_connections, show_network_info, get_bandwidth, get_connections
from vulnerability_scanner import VulnerabilityScanner, quick_vuln_scan
from arp_detector import ARPDetector, monitor_arp
from remote_server import NetGuardServer, NetGuardClient
from report_generator import PDFReportGenerator, generate_complete_report

# Inicializar colorama para colores en consola
init(autoreset=True)

def banner():
    """Muestra el banner principal de la herramienta"""
    print(f"""{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════════════╗
    ║  {Fore.WHITE}███╗   ██╗███████╗████████╗{Fore.CYAN}                                              ║
    ║  {Fore.WHITE}████╗  ██║██╔════╝╚══██╔══╝{Fore.CYAN}                                              ║
    ║  {Fore.WHITE}██╔██╗ ██║█████╗     ██║   {Fore.CYAN}                                              ║
    ║  {Fore.WHITE}██║╚██╗██║██╔══╝     ██║   {Fore.CYAN}                                              ║
    ║  {Fore.WHITE}██║ ╚████║███████╗   ██║   {Fore.CYAN}                                              ║
    ║  {Fore.WHITE}╚═╝  ╚═══╝╚══════╝   ╚═╝   {Fore.CYAN}                                              ║
    ║                                                                  ║
    ║           {Fore.GREEN}G U A R D   T O O L K I T   v 2 . 0{Fore.CYAN}                            ║
    ║        {Fore.YELLOW}Herramienta Profesional de Seguridad de Red{Fore.CYAN}                       ║
    ║                                                                  ║
    ║  {Fore.WHITE}Autor: NetGuard Team{Fore.CYAN}                                                   ║
    ║  {Fore.WHITE}Uso: Solo para auditorías autorizadas{Fore.CYAN}                                   ║
    ╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """)

def port_scanner_menu():
    """Menú del escáner de puertos"""
    while True:
        utils.print_header("ESCÁNER DE PUERTOS")
        print("1. Escaneo rápido (puertos comunes 1-1000)")
        print("2. Escaneo completo (1-65535) - Puede tomar varios minutos")
        print("3. Escanear red completa (detección de hosts activos)")
        print("4. Escaneo personalizado (define tu propio rango)")
        print("5. Escaneo TCP SYN (sigiloso) - Requiere permisos de administrador")
        print("6. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            target = input("IP objetivo: ")
            if target:
                quick_scan(target)
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '2':
            target = input("IP objetivo: ")
            if target:
                print(f"{Fore.YELLOW}[!] Esto puede tomar varios minutos. Por favor espera...")
                full_scan(target)
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '3':
            network = input("Red (ej: 192.168.1.0/24): ")
            if network:
                active = scan_network(network)
                print(f"\n{Fore.GREEN}[✓] Hosts encontrados: {len(active)}")
                if active:
                    print(f"{Fore.CYAN}[*] Lista de hosts activos:")
                    for host in active:
                        print(f"    • {host}")
            else:
                print(f"{Fore.RED}[!] Red no válida")
        
        elif choice == '4':
            target = input("IP objetivo: ")
            if target:
                try:
                    start = int(input("Puerto inicial: "))
                    end = int(input("Puerto final: "))
                    threads = int(input("Número de hilos (default 100): ") or 100)
                    scanner = PortScanner(target, start, end, threads)
                    scanner.scan()
                except ValueError:
                    print(f"{Fore.RED}[!] Error: Ingresa números válidos")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '5':
            print(f"{Fore.YELLOW}[!] Modo SYN scan en desarrollo para próxima versión")
            print(f"{Fore.CYAN}[*] Por ahora usa las opciones estándar")
        
        elif choice == '6':
            break
        
        input("\nPresiona Enter para continuar...")

def firewall_menu():
    """Menú de gestión del firewall"""
    fw = FirewallManager()
    
    while True:
        utils.print_header("GESTOR DE FIREWALL")
        print("1. Listar reglas actuales")
        print("2. Añadir regla (permitir puerto)")
        print("3. Bloquear puerto")
        print("4. Eliminar regla por nombre")
        print("5. Bloquear IP específica")
        print("6. Activar firewall (todas las redes)")
        print("7. Desactivar firewall (PELIGROSO - Solo para pruebas)")
        print("8. Ver estado del firewall")
        print("9. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            fw.list_rules()
        
        elif choice == '2':
            name = input("Nombre de la regla: ")
            port = input("Puerto: ")
            protocol = input("Protocolo (TCP/UDP): ").upper()
            if name and port and protocol in ['TCP', 'UDP']:
                fw.add_rule(name, port, protocol, "allow")
            else:
                print(f"{Fore.RED}[!] Datos inválidos")
        
        elif choice == '3':
            name = input("Nombre de la regla: ")
            port = input("Puerto: ")
            protocol = input("Protocolo (TCP/UDP): ").upper()
            if name and port and protocol in ['TCP', 'UDP']:
                fw.add_rule(name, port, protocol, "block")
            else:
                print(f"{Fore.RED}[!] Datos inválidos")
        
        elif choice == '4':
            name = input("Nombre de la regla a eliminar: ")
            if name:
                fw.delete_rule(name)
            else:
                print(f"{Fore.RED}[!] Nombre no válido")
        
        elif choice == '5':
            ip = input("IP a bloquear (ej: 192.168.1.100): ")
            if ip:
                fw.block_ip(ip)
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '6':
            fw.enable_firewall()
        
        elif choice == '7':
            fw.disable_firewall()
        
        elif choice == '8':
            result = subprocess.run('netsh advfirewall show allprofiles', shell=True, capture_output=True, text=True)
            print(result.stdout)
        
        elif choice == '9':
            break
        
        input("\nPresiona Enter para continuar...")

def monitor_menu():
    """Menú del monitor de red"""
    while True:
        utils.print_header("MONITOR DE RED")
        print("1. Ver conexiones activas (tiempo real)")
        print("2. Información detallada de red")
        print("3. Medir ancho de banda actual")
        print("4. Monitorear tráfico por interfaz")
        print("5. Ver estadísticas de red")
        print("6. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            monitor_connections()
        
        elif choice == '2':
            show_network_info()
        
        elif choice == '3':
            print(f"{Fore.CYAN}[*] Midiendo ancho de banda...")
            sent, recv = get_bandwidth()
            print(f"{Fore.GREEN}[✓] Resultados:")
            print(f"    Subida: {sent:.2f} KB/s ({sent/1024:.2f} MB/s)")
            print(f"    Descarga: {recv:.2f} KB/s ({recv/1024:.2f} MB/s)")
        
        elif choice == '4':
            print(f"{Fore.YELLOW}[!] Función en desarrollo para próxima versión")
            print(f"{Fore.CYAN}[*] Por ahora usa la opción 1 para ver conexiones")
        
        elif choice == '5':
            import psutil
            stats = psutil.net_io_counters(pernic=True)
            print(f"{Fore.CYAN}[*] Estadísticas por interfaz:")
            for interface, stat in stats.items():
                print(f"\n  {Fore.GREEN}{interface}:")
                print(f"    Bytes enviados: {stat.bytes_sent:,}")
                print(f"    Bytes recibidos: {stat.bytes_recv:,}")
                print(f"    Paquetes enviados: {stat.packets_sent:,}")
                print(f"    Paquetes recibidos: {stat.packets_recv:,}")
        
        elif choice == '6':
            break
        
        input("\nPresiona Enter para continuar...")

def vuln_scan_menu():
    """Menú de escaneo de vulnerabilidades"""
    while True:
        utils.print_header("ESCÁNER DE VULNERABILIDADES")
        print("1. Escaneo rápido de vulnerabilidades comunes")
        print("2. Escaneo completo (puertos + vulnerabilidades)")
        print("3. Escaneo de servicios expuestos")
        print("4. Prueba de credenciales débiles")
        print("5. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            target = input("IP objetivo: ")
            if target:
                vulns = quick_vuln_scan(target)
                if vulns:
                    print(f"\n{Fore.RED}[!] Se encontraron {len(vulns)} vulnerabilidades")
                    generar_reporte = input("\n¿Generar reporte PDF? (s/N): ")
                    if generar_reporte.lower() == 's':
                        try:
                            generator = PDFReportGenerator()
                            generator.add_vulnerabilities(vulns)
                            generator.generate(vulnerabilities=vulns)
                        except Exception as e:
                            print(f"{Fore.RED}[!] Error generando PDF: {e}")
                else:
                    print(f"{Fore.GREEN}[✓] No se encontraron vulnerabilidades comunes")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '2':
            target = input("IP objetivo: ")
            if target:
                print(f"{Fore.CYAN}[*] Realizando escaneo completo...")
                print(f"{Fore.YELLOW}[!] Esto puede tomar varios minutos...")
                
                # Escanear puertos
                from port_scanner import PortScanner
                scanner = PortScanner(target, 1, 1000, 100)
                open_ports = scanner.scan()
                
                # Escanear vulnerabilidades
                vuln_scanner = VulnerabilityScanner(target)
                all_vulns = []
                
                if open_ports:
                    vulns_port = vuln_scanner.check_open_ports_vulns(open_ports)
                    all_vulns.extend(vulns_port)
                
                vulns_http = vuln_scanner.check_http_vulnerabilities()
                all_vulns.extend(vulns_http)
                
                vulns_ssl = vuln_scanner.check_weak_ssl_tls()
                all_vulns.extend(vulns_ssl)
                
                # Generar reporte
                print(f"\n{Fore.GREEN}[✓] Escaneo completado")
                if all_vulns:
                    print(f"{Fore.RED}[!] Vulnerabilidades encontradas: {len(all_vulns)}")
                    generar = input("¿Generar reporte PDF? (s/N): ")
                    if generar.lower() == 's':
                        try:
                            generate_complete_report(target, open_ports, all_vulns, None)
                        except Exception as e:
                            print(f"{Fore.RED}[!] Error generando PDF: {e}")
                else:
                    print(f"{Fore.GREEN}[✓] No se encontraron vulnerabilidades")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '3':
            target = input("IP objetivo: ")
            if target:
                vuln_scanner = VulnerabilityScanner(target)
                # Solo servicios comunes
                common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
                vulns = vuln_scanner.check_open_ports_vulns(common_ports)
                if vulns:
                    print(f"{Fore.RED}[!] Servicios vulnerables encontrados:")
                    for vuln in vulns:
                        print(f"    • {vuln['type']} - {vuln['risk']}")
                else:
                    print(f"{Fore.GREEN}[✓] No se encontraron servicios vulnerables comunes")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '4':
            target = input("IP objetivo: ")
            if target:
                vuln_scanner = VulnerabilityScanner(target)
                vulns = vuln_scanner.check_default_credentials()
                if vulns:
                    print(f"{Fore.RED}[!] CREDENCIALES POR DEFECTO ENCONTRADAS:")
                    for vuln in vulns:
                        print(f"    • {vuln['detail']}")
                else:
                    print(f"{Fore.GREEN}[✓] No se detectaron credenciales por defecto")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '5':
            break
        
        input("\nPresiona Enter para continuar...")

def arp_menu():
    """Menú de detección ARP spoofing"""
    while True:
        utils.print_header("DETECTOR DE ARP SPOOFING")
        print("1. Iniciar monitoreo ARP en tiempo real")
        print("2. Escanear red actual (construir mapa MAC-IP)")
        print("3. Ver reporte completo ARP")
        print("4. Detectar posibles ataques MITM")
        print("5. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            print(f"{Fore.CYAN}[*] Iniciando detección ARP...")
            print(f"{Fore.YELLOW}[!] Presiona Ctrl+C para detener el monitoreo")
            detector = ARPDetector()
            detector.start_detection()
        
        elif choice == '2':
            print(f"{Fore.CYAN}[*] Escaneando red...")
            detector = ARPDetector()
            devices = detector.scan_network()
            print(f"\n{Fore.GREEN}[✓] Dispositivos encontrados: {len(devices)}")
            for ip, mac in devices.items():
                print(f"    {ip} -> {mac}")
        
        elif choice == '3':
            print(f"{Fore.CYAN}[*] Generando reporte ARP...")
            detector = ARPDetector()
            detector.scan_network()
            report = detector.get_report()
            
            print(f"\n{Fore.CYAN}[*] REPORTE ARP:")
            print(f"  {Fore.WHITE}Dispositivos detectados: {report['total_devices']}")
            print(f"  {Fore.WHITE}Eventos sospechosos: {report['suspicious_events']}")
            
            if report['suspicious_events'] > 0:
                print(f"\n{Fore.RED}[!] ¡ALERTA! Se detectaron posibles intentos de ARP Spoofing:")
                for event in report['events']:
                    print(f"    • IP: {event['ip']}")
                    print(f"      MAC esperada: {event['expected_mac']}")
                    print(f"      MAC detectada: {event['detected_mac']}")
            
            generar_pdf = input("\n¿Generar reporte PDF? (s/N): ")
            if generar_pdf.lower() == 's':
                try:
                    generator = PDFReportGenerator()
                    generator.add_arp_analysis(report)
                    generator.generate(arp_analysis=report)
                except Exception as e:
                    print(f"{Fore.RED}[!] Error generando PDF: {e}")
        
        elif choice == '4':
            print(f"{Fore.CYAN}[*] Analizando posibles MITM...")
            print(f"{Fore.YELLOW}[!] Verificando consistencia de tabla ARP...")
            detector = ARPDetector()
            detector.scan_network()
            report = detector.get_report()
            
            if report['suspicious_events'] > 0:
                print(f"{Fore.RED}[!] ¡POSIBLE ATAQUE MITM DETECTADO!")
                print(f"{Fore.RED}[*] Se recomienda:")
                print("    1. Revisar equipos en la red")
                print("    2. Bloquear MACs sospechosas")
                print("    3. Usar comunicaciones cifradas")
                print("    4. Configurar ARP estático en equipos críticos")
            else:
                print(f"{Fore.GREEN}[✓] No se detectaron anomalías ARP")
        
        elif choice == '5':
            break
        
        input("\nPresiona Enter para continuar...")

def remote_menu():
    """Menú de monitoreo remoto"""
    while True:
        utils.print_header("MONITOREO REMOTO")
        print("1. Iniciar servidor (modo escucha)")
        print("2. Conectar a servidor remoto (modo cliente)")
        print("3. Información del modo remoto")
        print("4. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            print(f"{Fore.CYAN}[*] Configuración del servidor:")
            port = input("Puerto (default 9999): ") or "9999"
            password = input("Contraseña (default admin123): ") or "admin123"
            
            try:
                port = int(port)
                print(f"\n{Fore.GREEN}[✓] Iniciando servidor...")
                server = NetGuardServer(host='0.0.0.0', port=port, password=password)
                server.start()
            except ValueError:
                print(f"{Fore.RED}[!] Puerto inválido")
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {e}")
        
        elif choice == '2':
            print(f"{Fore.CYAN}[*] Configuración del cliente:")
            server_ip = input("IP del servidor: ")
            port = input("Puerto (default 9999): ") or "9999"
            password = input("Contraseña: ")
            
            if server_ip:
                try:
                    port = int(port)
                    client = NetGuardClient(server_ip, port, password)
                    client.interactive_mode()
                except ValueError:
                    print(f"{Fore.RED}[!] Puerto inválido")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error: {e}")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '3':
            utils.print_header("MODO REMOTO - AYUDA")
            print("Comandos disponibles en modo cliente:")
            print(f"  {Fore.GREEN}scan <IP>{Fore.WHITE} - Escanea puertos de una IP")
            print(f"  {Fore.GREEN}connections{Fore.WHITE} - Muestra conexiones activas")
            print(f"  {Fore.GREEN}bandwidth{Fore.WHITE} - Mide ancho de banda")
            print(f"  {Fore.GREEN}info{Fore.WHITE} - Información del sistema remoto")
            print(f"  {Fore.GREEN}block_ip <IP>{Fore.WHITE} - Bloquea IP en el servidor")
            print(f"  {Fore.GREEN}help{Fore.WHITE} - Muestra esta ayuda")
            print(f"  {Fore.GREEN}exit{Fore.WHITE} - Desconectar")
            print(f"\n{Fore.YELLOW}[!] Requiere que el servidor esté ejecutándose")
        
        elif choice == '4':
            break
        
        input("\nPresiona Enter para continuar...")

def report_menu():
    """Menú de generación de reportes"""
    while True:
        utils.print_header("GENERADOR DE REPORTES PDF")
        print("1. Generar reporte completo (recomendado)")
        print("2. Generar reporte solo de vulnerabilidades")
        print("3. Generar reporte de escaneo de puertos")
        print("4. Ver reportes guardados")
        print("5. Volver al menú principal")
        
        choice = input("\n[NetGuard] Opción: ")
        
        if choice == '1':
            target = input("IP objetivo: ")
            if target:
                print(f"{Fore.CYAN}[*] Recolectando datos para reporte completo...")
                print(f"{Fore.YELLOW}[!] Esto puede tomar varios minutos...")
                
                try:
                    # Escanear puertos
                    print(f"{Fore.CYAN}[*] Escaneando puertos...")
                    from port_scanner import PortScanner
                    scanner = PortScanner(target, 1, 1000, 100)
                    open_ports = scanner.scan()
                    
                    # Escanear vulnerabilidades
                    print(f"{Fore.CYAN}[*] Escaneando vulnerabilidades...")
                    vuln_scanner = VulnerabilityScanner(target)
                    vulnerabilities = vuln_scanner.full_scan()
                    
                    # Análisis ARP solo para red local
                    arp_report = None
                    try:
                        import ipaddress
                        ip_obj = ipaddress.ip_address(target)
                        if ip_obj.is_private:
                            print(f"{Fore.CYAN}[*] Analizando red local...")
                            detector = ARPDetector()
                            detector.scan_network()
                            arp_report = detector.get_report()
                    except:
                        pass
                    
                    # Generar PDF
                    print(f"{Fore.CYAN}[*] Generando PDF...")
                    filename = generate_complete_report(target, open_ports, vulnerabilities, arp_report)
                    print(f"{Fore.GREEN}[✓] Reporte guardado en: {filename}")
                    
                except Exception as e:
                    print(f"{Fore.RED}[!] Error generando reporte: {e}")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '2':
            target = input("IP objetivo: ")
            if target:
                try:
                    vuln_scanner = VulnerabilityScanner(target)
                    vulnerabilities = vuln_scanner.full_scan()
                    
                    if vulnerabilities:
                        generator = PDFReportGenerator()
                        generator.add_vulnerabilities(vulnerabilities)
                        filename = generator.generate(vulnerabilities=vulnerabilities)
                        print(f"{Fore.GREEN}[✓] Reporte de vulnerabilidades guardado en: {filename}")
                    else:
                        print(f"{Fore.YELLOW}[!] No se encontraron vulnerabilidades")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error: {e}")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '3':
            target = input("IP objetivo: ")
            if target:
                try:
                    from port_scanner import PortScanner
                    scanner = PortScanner(target, 1, 1000, 100)
                    open_ports = scanner.scan()
                    
                    if open_ports:
                        generator = PDFReportGenerator()
                        generator.add_scan_results(open_ports)
                        filename = generator.generate(scan_results=open_ports)
                        print(f"{Fore.GREEN}[✓] Reporte de puertos guardado en: {filename}")
                    else:
                        print(f"{Fore.YELLOW}[!] No se encontraron puertos abiertos")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error: {e}")
            else:
                print(f"{Fore.RED}[!] IP no válida")
        
        elif choice == '4':
            import os
            reports_dir = "reports"
            if os.path.exists(reports_dir):
                reports = [f for f in os.listdir(reports_dir) if f.endswith('.pdf')]
                if reports:
                    print(f"\n{Fore.CYAN}[*] Reportes disponibles:")
                    for i, report in enumerate(reports, 1):
                        info = os.stat(os.path.join(reports_dir, report))
                        size = info.st_size / 1024
                        print(f"  {i}. {report} ({size:.1f} KB)")
                    
                    ver = input("\n¿Abrir reporte? (número o 0 para salir): ")
                    if ver.isdigit() and 1 <= int(ver) <= len(reports):
                        try:
                            os.startfile(os.path.join(reports_dir, reports[int(ver)-1]))
                            print(f"{Fore.GREEN}[✓] Abriendo reporte...")
                        except Exception as e:
                            print(f"{Fore.RED}[!] Error abriendo archivo: {e}")
                else:
                    print(f"{Fore.YELLOW}[!] No hay reportes guardados")
            else:
                print(f"{Fore.YELLOW}[!] No hay reportes guardados")
        
        elif choice == '5':
            break
        
        input("\nPresiona Enter para continuar...")

def about_menu():
    """Muestra información de la herramienta"""
    utils.print_header("ACERCA DE NETGUARD TOOLKIT")
    print(f"{Fore.CYAN}Nombre:{Fore.WHITE} NetGuard Toolkit")
    print(f"{Fore.CYAN}Versión:{Fore.WHITE} 2.0 (Complete Edition)")
    print(f"{Fore.CYAN}Autor:{Fore.WHITE} NetGuard Team")
    print(f"{Fore.CYAN}Plataforma:{Fore.WHITE} Windows 7/8/10/11")
    print(f"{Fore.CYAN}Lenguaje:{Fore.WHITE} Python 3.8+")
    print()
    print(f"{Fore.CYAN}Módulos incluidos:")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Escáner de puertos multi-thread")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Gestión avanzada de firewall (Windows)")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Monitor de red en tiempo real")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Escáner de vulnerabilidades básicas")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Detector de ARP Spoofing")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Servidor/cliente para monitoreo remoto")
    print(f"  {Fore.GREEN}•{Fore.WHITE} Generador de reportes PDF profesionales")
    print()
    print(f"{Fore.CYAN}Características:")
    print(f"  • Interfaz amigable con colores")
    print(f"  • Multithreading para escaneos rápidos")
    print(f"  • Logging de actividades")
    print(f"  • Reportes detallados en PDF")
    print(f"  • Comunicación segura cliente-servidor")
    print()
    print(f"{Fore.YELLOW}⚠️  ADVERTENCIA:")
    print(f"  Esta herramienta es SOLO PARA FINES EDUCATIVOS")
    print(f"  y auditorías de seguridad AUTORIZADAS.")
    print(f"  El uso no autorizado es ILEGAL.")
    print(f"  El autor no se hace responsable del mal uso.")
    print()
    print(f"{Fore.CYAN}Licencia:{Fore.WHITE} MIT")
    print(f"{Fore.CYAN}Repositorio:{Fore.WHITE} https://github.com/NetGuard/NetGuard-Toolkit")

def main():
    """Función principal de la aplicación"""
    # Verificar permisos de administrador
    if not utils.is_admin():
        print(f"{Fore.YELLOW}[!] No tienes permisos de administrador")
        print("[!] Algunas funciones (firewall, ARP) no estarán disponibles")
        print("[!] Se recomienda ejecutar como administrador")
        print()
        time.sleep(2)
    
    while True:
        banner()
        print(f"{Fore.WHITE}╔════════════════════════════════════════════════════════════╗")
        print(f"{Fore.WHITE}║  {Fore.CYAN}1.{Fore.WHITE} 🔍 Escáner de Puertos                                    {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}2.{Fore.WHITE} 🔥 Gestión de Firewall                                 {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}3.{Fore.WHITE} 📡 Monitor de Red                                      {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}4.{Fore.WHITE} 🛡️  Escáner de Vulnerabilidades                         {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}5.{Fore.WHITE} 🕵️  Detector ARP Spoofing                              {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}6.{Fore.WHITE} 🌐 Monitoreo Remoto                                    {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}7.{Fore.WHITE} 📊 Generador de Reportes PDF                           {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}8.{Fore.WHITE} ℹ️  Acerca de                                          {Fore.WHITE}║")
        print(f"{Fore.WHITE}║  {Fore.CYAN}9.{Fore.WHITE} 🚪 Salir                                               {Fore.WHITE}║")
        print(f"{Fore.WHITE}╚════════════════════════════════════════════════════════════╝")
        
        choice = input(f"\n{Fore.CYAN}[NetGuard] Selecciona una opción (1-9): {Fore.WHITE}")
        
        if choice == '1':
            port_scanner_menu()
        elif choice == '2':
            firewall_menu()
        elif choice == '3':
            monitor_menu()
        elif choice == '4':
            vuln_scan_menu()
        elif choice == '5':
            arp_menu()
        elif choice == '6':
            remote_menu()
        elif choice == '7':
            report_menu()
        elif choice == '8':
            about_menu()
            input("\nPresiona Enter para continuar...")
        elif choice == '9':
            print(f"\n{Fore.GREEN}[✓] ¡Gracias por usar NetGuard Toolkit!")
            print(f"{Fore.GREEN}[✓] Reportes guardados en la carpeta 'reports'")
            print(f"{Fore.CYAN}[*] ¡Hasta luego! 👋")
            utils.log_activity("Herramienta cerrada correctamente")
            sys.exit(0)
        else:
            print(f"{Fore.RED}[!] Opción no válida. Por favor elige 1-9")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Interrupción detectada. Saliendo...")
        utils.log_activity("Herramienta interrumpida por usuario")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] Error fatal: {e}")
        utils.log_activity(f"ERROR FATAL: {e}")
        input("Presiona Enter para salir...")
        sys.exit(1)
