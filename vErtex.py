import requests, os, urllib3, socket, ssl
import dns.resolver
from colorama import Fore, Style, init
from fpdf import FPDF
from datetime import datetime
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def show_banner():
    os.system('clear')
    print(f"""{Fore.CYAN}{Style.BRIGHT}
    ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗
    ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
    ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝ 
    ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗ 
     ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗
      ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ v4.1
    {Fore.WHITE}The Ultimate Security Suite | {Fore.RED}Author: albertChOXrX
    """)

class UltraReport(FPDF):
    def header(self):
        self.set_fill_color(15, 25, 35)
        self.rect(0, 0, 210, 35, 'F')
        self.set_font('Arial', 'B', 22)
        self.set_text_color(255, 255, 255)
        self.cell(0, 15, 'vErtex | ADVANCED INTELLIGENCE', 0, 1, 'L')
        self.set_font('Arial', '', 9)
        self.cell(0, 5, f'Audit ID: {datetime.now().strftime("%Y%m%d%H%M")}', 0, 0, 'L')
        self.cell(0, 5, f'Fecha: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}  ', 0, 1, 'R')
        self.ln(12)

    def draw_section(self, title):
        self.ln(5)
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(240, 240, 240)
        self.set_text_color(15, 25, 35)
        self.cell(0, 10, f"  {title.upper()}", 0, 1, 'L', True)
        self.ln(3)

class vErtexEngine:
    def __init__(self, target):
        # Normalizar entrada para manejar subdominios y rutas
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        parsed = urlparse(target)
        self.full_url = target
        self.target = parsed.netloc
        
        self.results = []
        self.pdf = UltraReport()
        self.screenshot_path = None
        self.target_ip = "N/A"
        self.scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def log(self, cat, msg, level="INFO"):
        self.results.append({"cat": cat, "msg": msg, "level": level})
        color = Fore.RED if level == "CRITICAL" else Fore.YELLOW if level == "MEDIUM" else Fore.GREEN
        print(f"{color}[*] {cat}: {msg}")

    def run_all(self):
        # 1. INFRAESTRUCTURA
        try:
            self.target_ip = socket.gethostbyname(self.target)
            self.log("NETWORK", f"IP Address: {self.target_ip}", "SUCCESS")
        except: 
            self.log("NETWORK", f"No se pudo resolver el dominio: {self.target}", "CRITICAL")
            return False

        # 2. GEOLOCALIZACION
        try:
            data = requests.get(f"http://ip-api.com/json/{self.target_ip}", timeout=5).json()
            if data['status'] == 'success':
                self.log("GEO", f"Country: {data['country']} ({data['city']})", "SUCCESS")
                self.log("GEO", f"ISP: {data['isp']}", "INFO")
        except: pass

        # 3. PUERTOS
        ports = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL"}
        for port, svc in ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            if s.connect_ex((self.target_ip, port)) == 0:
                self.log("PORT", f"Service {svc} OPEN on {port}", "MEDIUM")
            s.close()

        # 4. CAPTURA VISUAL (Usando URL completa)
        from selenium import webdriver
        from selenium.webdriver.firefox.options import Options
        import time
        options = Options()
        options.add_argument("--headless")
        try:
            self.log("VISUAL", f"Capturando: {self.full_url}", "INFO")
            dr = webdriver.Firefox(options=options)
            dr.get(self.full_url)
            time.sleep(3)
            self.screenshot_path = f"ev_{self.target.replace('.','_')}.png"
            dr.save_screenshot(self.screenshot_path)
            dr.quit()
        except: self.log("VISUAL", "Error en captura", "MEDIUM")
        return True

    def generate_pdf(self):
        self.pdf.add_page()
        self.pdf.set_fill_color(30, 40, 50)
        self.pdf.set_text_color(255, 255, 255)
        self.pdf.set_font("Arial", 'B', 12)
        self.pdf.cell(190, 12, f"  URL: {self.full_url}", 0, 1, 'L', True)
        self.pdf.set_text_color(0)

        self.pdf.draw_section("Digital Evidence")
        if self.screenshot_path:
            self.pdf.image(self.screenshot_path, x=15, w=180, h=95)
            self.pdf.ln(100)

        self.pdf.draw_section("Technical Findings")
        self.pdf.set_font("Arial", 'B', 10)
        self.pdf.set_fill_color(220, 225, 230)
        self.pdf.cell(35, 8, " CATEGORY", 1, 0, 'L', True)
        self.pdf.cell(120, 8, " FINDING", 1, 0, 'L', True)
        self.pdf.cell(35, 8, " SEVERITY", 1, 1, 'L', True)

        self.pdf.set_font("Arial", '', 9)
        for r in self.results:
            self.pdf.cell(35, 7, f" {r['cat']}", 1, 0)
            self.pdf.cell(120, 7, f" {r['msg'][:70]}", 1, 0)
            self.pdf.cell(35, 7, f" {r['level']}", 1, 1)

        name = f"Reporte_vErtex_{self.target.replace('.','_')}.pdf"
        self.pdf.output(name)
        print(f"\n{Fore.CYAN}[+] Reporte listo: {name}")

def main():
    show_banner()
    t = input(f"{Fore.YELLOW}🎯 URL/Link: ")
    if not t: return
    v = vErtexEngine(t)
    if v.run_all():
        v.generate_pdf()

if __name__ == "__main__":
    main()
