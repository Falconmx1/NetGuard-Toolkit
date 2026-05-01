import subprocess
import re
from colorama import Fore
import utils

class FirewallManager:
    def __init__(self):
        self.check_admin()
    
    def check_admin(self):
        if not utils.is_admin():
            print(f"{Fore.RED}[!] Se requieren permisos de administrador para gestionar el firewall")
            return False
        return True
    
    def add_rule(self, name, port, protocol="TCP", action="allow"):
        """Añade una regla al firewall"""
        if not self.check_admin():
            return False
        
        direction = "in"
        action_str = "allow" if action == "allow" else "block"
        
        cmd = f'netsh advfirewall firewall add rule name="{name}" dir={direction} protocol={protocol} localport={port} action={action_str}'
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if "Ok" in result.stdout:
                print(f"{Fore.GREEN}[✓] Regla añadida: {name} - Puerto {port}/{protocol} ({action_str})")
                utils.log_activity(f"Regla firewall añadida: {name} - Puerto {port}")
                return True
            else:
                print(f"{Fore.RED}[!] Error: {result.stdout}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
            return False
    
    def delete_rule(self, name):
        """Elimina una regla del firewall"""
        if not self.check_admin():
            return False
        
        cmd = f'netsh advfirewall firewall delete rule name="{name}"'
        
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"{Fore.GREEN}[✓] Regla eliminada: {name}")
            utils.log_activity(f"Regla firewall eliminada: {name}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Error: {e}")
            return False
    
    def list_rules(self):
        """Lista todas las reglas del firewall"""
        if not self.check_admin():
            return []
        
        cmd = 'netsh advfirewall firewall show rule name=all'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        rules = []
        current_rule = {}
        
        for line in result.stdout.split('\n'):
            if 'Rule Name:' in line:
                if current_rule:
                    rules.append(current_rule)
                current_rule = {'name': line.split('Rule Name:')[1].strip()}
            elif 'LocalPort:' in line and current_rule:
                current_rule['port'] = line.split('LocalPort:')[1].strip()
            elif 'Protocol:' in line and current_rule:
                current_rule['protocol'] = line.split('Protocol:')[1].strip()
            elif 'Action:' in line and current_rule:
                current_rule['action'] = line.split('Action:')[1].strip()
        
        if current_rule:
            rules.append(current_rule)
        
        print(f"{Fore.CYAN}[*] Reglas del firewall:")
        for rule in rules:
            if 'port' in rule:
                print(f"  - {rule['name']}: Puerto {rule['port']} ({rule.get('protocol', 'Any')}) - {rule.get('action', 'Unknown')}")
        
        return rules
    
    def enable_firewall(self):
        """Activa el firewall"""
        if not self.check_admin():
            return False
        
        cmd = 'netsh advfirewall set allprofiles state on'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"{Fore.GREEN}[✓] Firewall activado")
        utils.log_activity("Firewall activado")
        return True
    
    def disable_firewall(self):
        """Desactiva el firewall (peligroso!)"""
        if not self.check_admin():
            return False
        
        confirm = input(f"{Fore.RED}[!] ¿Seguro que quieres desactivar el firewall? (s/N): ")
        if confirm.lower() == 's':
            cmd = 'netsh advfirewall set allprofiles state off'
            subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"{Fore.RED}[!] Firewall desactivado - ¡RIESGO DE SEGURIDAD!")
            utils.log_activity("¡FIREWALL DESACTIVADO!")
            return True
        return False
    
    def block_ip(self, ip):
        """Bloquea una IP específica"""
        if not self.check_admin():
            return False
        
        cmd = f'netsh advfirewall firewall add rule name="Block_IP_{ip}" dir=in remoteip={ip} action=block'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if "Ok" in result.stdout:
            print(f"{Fore.GREEN}[✓] IP bloqueada: {ip}")
            utils.log_activity(f"IP bloqueada: {ip}")
            return True
        else:
            print(f"{Fore.RED}[!] Error al bloquear IP")
            return False
