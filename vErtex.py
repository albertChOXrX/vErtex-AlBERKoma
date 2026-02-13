import requests
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
                                    
        {Fore.WHITE}Visual & Stealth Recon v2.2
        {Fore.RED}Nombre del Programa: vErtex
        {Fore.RED}Autor: albertChOXrX
{Style.RESET_ALL}"""
    print(banner)

class RAJA_Report(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'vErtex: WEB VISUAL AUDIT', 0, 1, 'C')
        self.ln(5)

class RajaEngine:
    def __init__(self, target):
        self.target = target.replace("https://", "").replace("http://", "").strip("/")
        self.results = []
        self.pdf = RAJA_Report()
        self.screenshot_path = None

    def log(self, text, status="info"):
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.results.append((status, text))
        if status == "success": print(Fore.GREEN + f" [{timestamp}][✓] {text}")
        elif status == "error": print(Fore.RED + f" [{timestamp}][✗] {text}")
        else: print(Fore.BLUE + f" [{timestamp}][*] {text}")

    def get_geo(self):
        self.log(f"Obteniendo ubicación del servidor...")
        try:
            ip = socket.gethostbyname(self.target)
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            if data.get('status') == 'success':
                info = f"IP: {ip} | {data['city']}, {data['country']} ({data['isp']})"
                self.log(info, "success")
            else:
                self.log("No se pudo geolocalizar.", "error")
        except: self.log("Error al rastrear IP", "error")

    def analyze_headers(self):
        self.log(f"Analizando identidad del servidor...")
        url = f"https://{self.target}"
        try:
            res = requests.get(url, timeout=10, verify=False)
            server = res.headers.get('Server', 'Desconocido')
            self.log(f"Servidor Web detectado: {server}", "success")
        except: self.log("Error al obtener cabeceras", "error")

    def take_screenshot(self):
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        import time
        self.log("Generando vista previa visual (Segura)...")
        options = Options()
        options.add_argument("--headless")
        options.set_preference("accept_insecure_certs", True)
        try:
            driver = webdriver.Firefox(options=options)
            driver.get(f"http://{self.target}")
            time.sleep(5) # Tiempo para que cargue el contenido
            path = f"vista_{self.target.replace('.', '_')}.png"
            driver.save_screenshot(path)
            self.screenshot_path = path
            driver.quit()
            self.log(f"Captura completada con éxito", "success")
        except Exception as e: self.log(f"No se pudo generar la vista previa: {e}", "error")

    def generate_pdf(self):
        self.pdf.add_page()
        self.pdf.set_font("Arial", 'B', 14)
        self.pdf.cell(0, 10, f"ANALISIS DE: {self.target}", ln=True)
        self.pdf.ln(10)
        
        if self.screenshot_path:
            self.pdf.image(self.screenshot_path, x=10, w=180)
            self.pdf.ln(110) # Espacio después de la imagen

        self.pdf.set_font("Arial", 'B', 12)
        self.pdf.cell(0, 10, "Detalles del Hallazgo:", ln=True)
        for status, text in self.results:
            self.pdf.set_font("Arial", size=10)
            clean_text = text.encode('latin-1', 'ignore').decode('latin-1')
            self.pdf.multi_cell(0, 8, f" - {clean_text}")

        filename = f"Vista_vErtex_{self.target.replace('.', '_')}.pdf"
        self.pdf.output(filename)
        print(Fore.YELLOW + f"\n[+] vErtex: Reporte visual listo en {filename}")

def main():
    show_banner()
    target_input = input(Fore.YELLOW + "🎯 Ingrese la URL para inspeccionar: ")
    if not target_input: return

    engine = RajaEngine(target_input)
    
    engine.get_geo()
    engine.analyze_headers()
    engine.take_screenshot()
    engine.generate_pdf()

if __name__ == "__main__":
    main()
