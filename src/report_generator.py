from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os
from colorama import Fore
import utils

class PDFReportGenerator:
    def __init__(self, filename=None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reports/netguard_report_{timestamp}.pdf"
        
        # Crear directorio reports si no existe
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        self.filename = filename
        self.doc = SimpleDocTemplate(filename, pagesize=letter)
        self.styles = getSampleStyleSheet()
        self.story = []
        
        # Estilos personalizados
        self.add_custom_styles()
    
    def add_custom_styles(self):
        """Añade estilos personalizados"""
        self.styles.add(ParagraphStyle(
            name='Title',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a5490'),
            alignment=1,  # Centro
            spaceAfter=30
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontWeight='bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontWeight='bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontWeight='bold'
        ))
    
    def add_header(self):
        """Añade cabecera del reporte"""
        self.story.append(Paragraph("NetGuard Toolkit", self.styles['Title']))
        self.story.append(Paragraph("Reporte de Seguridad de Red", self.styles['Title']))
        self.story.append(Spacer(1, 0.2*inch))
        
        fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        self.story.append(Paragraph(f"<b>Fecha:</b> {fecha}", self.styles['Normal']))
        self.story.append(Paragraph(f"<b>Host:</b> {os.uname().nodename if hasattr(os, 'uname') else 'Windows'}", self.styles['Normal']))
        self.story.append(Spacer(1, 0.3*inch))
    
    def add_scan_results(self, scan_data):
        """Añade resultados de escaneo"""
        self.story.append(Paragraph("1. Escaneo de Puertos", self.styles['Heading2']))
        self.story.append(Spacer(1, 0.1*inch))
        
        if scan_data and len(scan_data) > 0:
            data = [['Puerto', 'Servicio', 'Estado']]
            for port in scan_data:
                from port_scanner import PortScanner
                scanner = PortScanner('temp')
                service = scanner.get_service_name(port) if hasattr(scanner, 'get_service_name') else 'Desconocido'
                data.append([str(port), service, 'ABIERTO'])
            
            table = Table(data)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            self.story.append(table)
        else:
            self.story.append(Paragraph("No se encontraron puertos abiertos", self.styles['Normal']))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def add_vulnerabilities(self, vulns):
        """Añade vulnerabilidades encontradas"""
        self.story.append(Paragraph("2. Vulnerabilidades Encontradas", self.styles['Heading2']))
        self.story.append(Spacer(1, 0.1*inch))
        
        if vulns and len(vulns) > 0:
            for i, vuln in enumerate(vulns, 1):
                # Determinar estilo según riesgo
                if vuln['risk'] == 'CRITICO' or vuln['risk'] == 'ALTO':
                    risk_style = 'RiskHigh'
                elif vuln['risk'] == 'MEDIO':
                    risk_style = 'RiskMedium'
                else:
                    risk_style = 'RiskLow'
                
                self.story.append(Paragraph(f"<b>{i}. {vuln['type']}</b>", self.styles['Normal']))
                self.story.append(Paragraph(f"<b>Riesgo:</b> <font color='red'>{vuln['risk']}</font>", self.styles['Normal']))
                self.story.append(Paragraph(f"<b>Detalle:</b> {vuln['detail']}", self.styles['Normal']))
                self.story.append(Paragraph(f"<b>Solución:</b> {vuln['solution']}", self.styles['Normal']))
                self.story.append(Spacer(1, 0.1*inch))
        else:
            self.story.append(Paragraph("No se encontraron vulnerabilidades", self.styles['Normal']))
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def add_arp_analysis(self, arp_data):
        """Añade análisis ARP"""
        self.story.append(Paragraph("3. Análisis ARP", self.styles['Heading2']))
        self.story.append(Spacer(1, 0.1*inch))
        
        if arp_data:
            self.story.append(Paragraph(f"<b>Dispositivos encontrados:</b> {arp_data.get('total_devices', 0)}", self.styles['Normal']))
            self.story.append(Paragraph(f"<b>Eventos sospechosos:</b> {arp_data.get('suspicious_events', 0)}", self.styles['Normal']))
            
            if arp_data.get('suspicious_events', 0) > 0:
                self.story.append(Paragraph("<b><font color='red'>¡ALERTA! Se detectó posible ARP Spoofing</font></b>", self.styles['Normal']))
                
                for event in arp_data.get('events', []):
                    self.story.append(Paragraph(f"• IP: {event['ip']} - MAC falsa detectada", self.styles['Normal']))
            
            # Tabla de dispositivos
            self.story.append(Paragraph("<b>Dispositivos en la red:</b>", self.styles['Normal']))
            data = [['IP', 'MAC Address']]
            for ip, mac in arp_data.get('mac_table', {}).items():
                data.append([ip, mac])
            
            if len(data) > 1:
                table = Table(data)
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                self.story.append(table)
        
        self.story.append(Spacer(1, 0.2*inch))
    
    def add_recommendations(self):
        """Añade recomendaciones de seguridad"""
        self.story.append(PageBreak())
        self.story.append(Paragraph("4. Recomendaciones de Seguridad", self.styles['Heading2']))
        self.story.append(Spacer(1, 0.1*inch))
        
        recommendations = [
            "• Mantener el sistema operativo actualizado con los últimos parches",
            "• Usar firewalls y mantener reglas actualizadas",
            "• Cambiar contraseñas por defecto en todos los servicios",
            "• Implementar autenticación de dos factores cuando sea posible",
            "• Monitorear regularmente conexiones de red sospechosas",
            "• Realizar copias de seguridad periódicas",
            "• Usar cifrado SSL/TLS en todas las comunicaciones",
            "• Deshabilitar servicios no utilizados"
        ]
        
        for rec in recommendations:
            self.story.append(Paragraph(rec, self.styles['Normal']))
            self.story.append(Spacer(1, 0.05*inch))
    
    def generate(self, scan_results=None, vulnerabilities=None, arp_analysis=None):
        """Genera el PDF completo"""
        print(f"{Fore.CYAN}[*] Generando reporte PDF...")
        
        self.add_header()
        
        if scan_results:
            self.add_scan_results(scan_results)
        
        if vulnerabilities:
            self.add_vulnerabilities(vulnerabilities)
        
        if arp_analysis:
            self.add_arp_analysis(arp_analysis)
        
        self.add_recommendations()
        
        # Construir PDF
        self.doc.build(self.story)
        
        print(f"{Fore.GREEN}[✓] Reporte generado: {self.filename}")
        utils.log_activity(f"Reporte PDF generado: {self.filename}")
        
        return self.filename

def generate_complete_report(target_ip, scan_results, vulnerabilities, arp_data):
    """Genera reporte completo con todos los datos"""
    generator = PDFReportGenerator()
    return generator.generate(scan_results, vulnerabilities, arp_data)
