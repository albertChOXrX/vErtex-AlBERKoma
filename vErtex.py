import requests, os, urllib3, socket, ssl, re, time
from colorama import Fore, Style, init
from fpdf import FPDF
from datetime import datetime
from urllib.parse import urlparse

# --- CONFIGURACIÓN ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def show_banner():
    os.system('clear' if os.name != 'nt' else 'cls')
    # TU BANNER ORIGINAL DE LA v4.1 / v4.2
    print(f"""{Fore.CYAN}{Style.BRIGHT}
    ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗
    ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
    ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝ 
    ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
     ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
      ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ v4.2
    {Fore.WHITE}The Ultimate Security Suite | {Fore.RED}Author: albertChOXrX
    """)

class UltraReport(FPDF):
    def header(self):
        # Cabecera profesional azul oscuro (como tu imagen)
        self.set_fill_color(15, 25, 35)
        self.rect(0, 0, 210, 40, 'F')
        self.set_font('Arial', 'B', 24)
        self.set_text_color(255, 255, 255)
        self.cell(0, 20, 'vErtex | ADVANCED INTELLIGENCE', 0, 1, 'L')
        self.set_font('Arial', '', 10)
        self.cell(95, 5, f'Audit ID: {datetime.now().strftime("%Y%m%d%H%M")}', 0, 0, 'L')
        self.cell(95, 5, f'Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ', 0, 1, 'R')
        self.ln(15)

    def draw_section(self, title):
        self.ln(5)
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(15, 25, 35)
        self.cell(0, 10, f"  {title.upper()}", 0, 1, 'L', True)
        self.ln(3)

class vErtexEngine:
    def __init__(self, target):
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        parsed = urlparse(target)
        self.full_url = target
        self.target_domain = parsed.netloc
        self.results = []
        self.pdf = UltraReport()
        self.screenshot_path = None
        self.target_ip = "N/A"

    def log(self, cat, msg, level="INFO"):
        self.results.append({"cat": cat, "msg": msg, "level": level})
        color = Fore.RED if level == "CRITICAL" else Fore.YELLOW if level == "MEDIUM" else Fore.GREEN
        print(f"{Fore.WHITE}[{color}{cat}{Fore.WHITE}] {msg}")

    def run_all(self):
        # 1. INFRAESTRUCTURA & DNS
        try:
            self.target_ip = socket.gethostbyname(self.target_domain)
            self.log("NETWORK", f"IP Address: {self.target_ip}", "SUCCESS")
            self.log("DNS", f"A Record: {self.target_ip}", "SUCCESS")
        except: 
            self.log("NETWORK", "Error resolviendo dominio", "CRITICAL")
            return False

        # 2. GEO & ISP
        try:
            data = requests.get(f"http://ip-api.com/json/{self.target_ip}", timeout=5).json()
            if data['status'] == 'success':
                self.log("GEO", f"Location: {data['country']} ({data['city']})", "SUCCESS")
                self.log("GEO", f"ISP: {data['isp']}", "INFO")
        except: pass

        # 3. PUERTOS & SERVICIOS
        for port in [22, 80, 443, 3306]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            if s.connect_ex((self.target_ip, port)) == 0:
                self.log("PORT", f"Port {port} is OPEN", "MEDIUM")
            s.close()

        # 4. VULNERABILIDAD & FORENSIC
        try:
            r = requests.get(self.full_url, timeout=5, verify=False)
            banner = r.headers.get('Server', 'Not Detected')
            self.log("FORENSIC", f"Server Banner: {banner}", "SUCCESS")
            
            if 'X-Frame-Options' not in r.headers:
                self.log("VULN", "Clickjacking Risk (Missing X-Frame-Options)", "MEDIUM")
            if 'Content-Security-Policy' not in r.headers:
                self.log("VULN", "XSS Risk (Missing CSP)", "CRITICAL")
        except: pass

        # 5. GUARDIAN (Malware Analyzer)
        try:
            r = requests.get(self.full_url, timeout=5, verify=False)
            if "coinhive" in r.text.lower() or "eval(unescape(" in r.text.lower():
                self.log("MALWARE", "¡ALERTA! Código sospechoso detectado", "CRITICAL")
            else:
                self.log("MALWARE", "Código fuente analizado y limpio", "SUCCESS")
        except: pass

        # 6. CAPTURA VISUAL (Selenium)
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts = Options()
        opts.add_argument("--headless")
        try:
            self.log("VISUAL", "Generando evidencia visual...", "INFO")
            dr = webdriver.Chrome(options=opts)
            dr.get(self.full_url)
            time.sleep(2)
            self.screenshot_path = f"ev_{self.target_domain.replace('.','_')}.png"
            dr.save_screenshot(self.screenshot_path)
            dr.quit()
        except: self.log("VISUAL", "No se pudo realizar la captura", "MEDIUM")

        return True

    def generate_pdf(self):
        self.pdf.add_page()
        
        # Objetivo
        self.pdf.set_fill_color(30, 40, 50)
        self.pdf.set_text_color(255, 255, 255)
        self.pdf.set_font("Arial", 'B', 12)
        self.pdf.cell(190, 12, f"  TARGET URL: {self.full_url}", 0, 1, 'L', True)
        self.pdf.set_text_color(0)

        # Evidencia Visual
        self.pdf.draw_section("Digital Evidence (Capture)")
        if self.screenshot_path and os.path.exists(self.screenshot_path):
            self.pdf.image(self.screenshot_path, x=15, w=180)
            self.pdf.ln(100)

        # Matriz de Vulnerabilidades (Igual que tu captura)
        self.pdf.draw_section("Technical Findings & Vulnerability Matrix")
        self.pdf.set_font("Arial", 'B', 10)
        self.pdf.set_fill_color(220, 225, 230)
        self.pdf.cell(35, 10, " CATEGORY", 1, 0, 'L', True)
        self.pdf.cell(125, 10, " FINDING", 1, 0, 'L', True)
        self.pdf.cell(30, 10, " SEVERITY", 1, 1, 'L', True)

        self.pdf.set_font("Arial", '', 9)
        for r in self.results:
            # Colores de texto según nivel (Fiel a la imagen)
            if r['level'] == "CRITICAL": self.pdf.set_text_color(200, 0, 0)
            elif r['level'] == "MEDIUM": self.pdf.set_text_color(200, 150, 0)
            elif r['level'] == "SUCCESS": self.pdf.set_text_color(0, 128, 0)
            else: self.pdf.set_text_color(0, 0, 0)

            self.pdf.cell(35, 8, f" {r['cat']}", 1, 0)
            self.pdf.cell(125, 8, f" {r['msg'][:75]}", 1, 0)
            self.pdf.cell(30, 8, f" {r['level']}", 1, 1)

        name = f"Reporte_vErtex_{self.target_domain.replace('.','_')}.pdf"
        self.pdf.output(name)
        print(f"\n{Fore.CYAN}[+] AUDITORÍA COMPLETADA. REPORTE: {name}")

def main():
    show_banner()
    t = input(f"{Fore.YELLOW}🎯 Introduzca Objetivo: ")
    if not t: return
    v = vErtexEngine(t)
    if v.run_all():
        v.generate_pdf()

if __name__ == "__main__":
    main()
