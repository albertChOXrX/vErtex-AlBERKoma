import requests
import dns.resolver
import os
import urllib3
import socket
from colorama import Fore, Style, init
from fpdf import FPDF
from datetime import datetime

# Configuración inicial
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def show_banner():
    os.system('clear')
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
        __   __        _            
        \ \ / /__ _ __| |_ _____ __ 
         \ V / -_) '_ \  _/ -_) \ / 
          \_/\___|_|  \__\___/_\_\  
                                    
        {Fore.WHITE}Auditoría de Superficie de Ataque v2.2
        {Fore.RED}Nombre del Programa: vErtex
        {Fore.RED}Autor: albertChOXrX
{Style.RESET_ALL}"""
    print(banner)

class RAJA_Report(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'vErtex: SECURITY AUDIT REPORT', 0, 1, 'C')
        self.ln(5)

class RajaEngine:
    def __init__(self, target):
        self.target = target.replace("https://", "").replace("http://", "").strip("/")
        self.results = []
        self.pdf = RAJA_Report()
        self.screenshot_path = None
        self.target_ip = None

    def log(self, text, status="info"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.results.append((status, text))
        if status == "success": print(Fore.GREEN + f" [{timestamp}][✓] {text}")
        elif status == "error": print(Fore.RED + f" [{timestamp}][✗] {text}")
        else: print(Fore.BLUE + f" [{timestamp}][*] {text}")

    def get_geo(self):
        self.log(f"Rastreando ubicación del servidor...")
        try:
            self.target_ip = socket.gethostbyname(self.target)
            response = requests.get(f"http://ip-api.com/json/{self.target_ip}", timeout=5)
            data = response.json()
            if data.get('status') == 'success':
                info = f"IP: {self.target_ip} | {data['city']}, {data['country']} ({data['isp']})"
                self.log(info, "success")
            else:
                self.log("No se obtuvieron datos de geolocalización.", "error")
        except Exception as e:
            self.log(f"Error en geo-módulo: {str(e)}", "error")

    # --- NUEVA FUNCIÓN: ESCANEO DE PUERTOS ---
    def scan_ports(self):
        self.log(f"Iniciando escaneo de puertos comunes en {self.target_ip}...")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080]
        found_any = False
        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((self.target_ip, port))
            if result == 0:
                self.log(f"Puerto Abierto Encontrado: {port}", "success")
                found_any = True
            s.close()
        if not found_any:
            self.log("No se detectaron puertos comunes abiertos.", "info")

    def analyze_headers(self):
        url = f"https://{self.target}"
        try:
            res = requests.get(url, timeout=10, verify=False)
            headers = res.headers
            self.log(f"Analizando cabeceras de seguridad...")
            checks = {"Content-Security-Policy": "XSS", "X-Frame-Options": "Clickjacking", "Strict-Transport-Security": "HSTS"}
            for h, desc in checks.items():
                if h in headers: self.log(f"{h}: OK", "success")
                else: self.log(f"{h}: AUSENTE (Riesgo: {desc})", "error")
        except: self.log("Error al conectar para cabeceras", "error")

    def dns_recon(self):
        self.log(f"Ejecutando DNS Recon...")
        try:
            answers = dns.resolver.resolve(self.target, 'A')
            for rdata in answers: self.log(f"Registro A: {rdata}", "success")
        except: self.log("No se encontraron registros DNS públicos", "error")

    def take_screenshot(self):
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        import time
        self.log("Capturando evidencia visual (Headless Mode)...")
        options = Options()
        options.add_argument("--headless")
        options.set_preference("accept_insecure_certs", True)
        try:
            driver = webdriver.Firefox(options=options)
            driver.get(f"http://{self.target}")
            time.sleep(5)
            path = f"evidencia_{self.target.replace('.', '_')}.png"
            driver.save_screenshot(path)
            self.screenshot_path = path
            driver.quit()
            self.log(f"Captura guardada correctamente", "success")
        except Exception as e: self.log(f"Fallo en Selenium: {e}", "error")

    def generate_pdf(self):
        self.pdf.add_page()
        self.pdf.set_font("Arial", 'B', 14)
        self.pdf.cell(0, 10, f"OBJETIVO: {self.target}", ln=True)
        self.pdf.ln(5)
        
        if self.screenshot_path and os.path.exists(self.screenshot_path):
            self.pdf.image(self.screenshot_path, x=10, w=180)
            self.pdf.ln(10)

        for status, text in self.results:
            self.pdf.set_font("Arial", size=10)
            try:
                clean_text = text.encode('latin-1', 'ignore').decode('latin-1')
                self.pdf.multi_cell(0, 8, f"[{status.upper()}] {clean_text}")
            except: continue

        filename = f"Reporte_vErtex_{self.target.replace('.', '_')}.pdf"
        self.pdf.output(filename)
        print(Fore.YELLOW + f"\n[+] vErtex: Reporte final generado en {filename}")

def main():
    show_banner()
    target_input = input(Fore.YELLOW + "🎯 Ingrese URL objetivo: ")
    if not target_input: return

    engine = RajaEngine(target_input)

    # FLUJO v2.2
    engine.get_geo()         # Localiza
    engine.scan_ports()      # ESCANEA (Nuevo)
    engine.analyze_headers() # Seguridad
    engine.dns_recon()       # DNS
    engine.take_screenshot() # Foto
    engine.generate_pdf()    # Reporte

if __name__ == "__main__":
    main()
