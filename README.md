# 🦅 vErtex-AlBERKoma
> **Automated Reconnaissance & Forensic Reporting Tool**

vErtex es un motor de auditoría diseñado para analizar superficies de ataque web, realizar recon DNS y capturar evidencias visuales de sitios sospechosos (Phishing/Ngrok) ignorando bloqueos SSL.

### 🛠️ Características
* 🔍 **DNS Recon:** Registros A y MX.
* 🛡️ **Security Headers:** Análisis de CSP, HSTS y X-Frame.
* 📸 **Stealth Capture:** Captura de pantalla en modo Headless (Bypass SSL).
* 📄 **Auto-Reporting:** Generación de reporte forense en PDF.
# 🦅 vErtex v2.1
**vErtex** es una herramienta de auditoría de seguridad automatizada diseñada para el reconocimiento rápido de superficies de ataque web, análisis de cabeceras, geolocalización de servidores y generación de informes forenses en PDF.

---

## 🚀 Funcionalidades
* **Geolocalización IP:** Rastrea la ubicación física, ciudad, país e ISP del servidor objetivo.
* **DNS Recon:** Identificación de registros A y MX.
* **Análisis de Seguridad:** Verificación de cabeceras críticas (CSP, X-Frame-Options).
* **Captura de Pantalla:** Evidencia visual automática incluso en sitios con certificados SSL inválidos (Bypass).
* **Reporte PDF:** Generación automática de un informe profesional con todos los hallazgos.
---

## 🛠️ Instalación y Uso

Sigue estos pasos en tu terminal de Kali Linux:

### 1. Clonar el repositorio
```bash
git clone [https://github.com/albertChOXrX/vErtex-AlBERKoma.git]///(https://github.com/albertChOXrX/vErtex-AlBERKoma.git)
cd vErtex-AlBERKoma
pip install -r requirements.txt
python3 vErtex.py
```

📦 Requisitos previos
Para que la captura de pantalla funcione correctamente, necesitas tener instalado el driver de Firefox (Geckodriver):
sudo apt update
sudo apt install firefox-geckodriver
⚠️ Aviso Legal
Este programa ha sido creado exclusivamente con fines educativos y de auditoría ética. El autor no se hace responsable del mal uso de esta herramienta contra objetivos sin autorización previa.
