# 🦅 vErtex v4.0 - Titanium Edition
**Ultimate Automated Reconnaissance, Forensic & Vulnerability Suite**

**vErtex** es una suite avanzada de ciberseguridad diseñada para analistas y auditores éticos. Permite diseccionar una infraestructura web completa —desde la capa de red hasta la visual— generando informes forenses de alta fidelidad en formato PDF profesional.

---

## 🚀 Funcionalidades Elite (v4.0)

* **📡 Escaneo de Puertos (Nmap Style):** Identificación automática de servicios críticos abiertos (SSH, FTP, HTTP, MySQL, etc.).
* **🛡️ Matriz de Vulnerabilidades:** Análisis de debilidades estructurales (CSP, XSS Risk, Clickjacking) con clasificación de severidad (Crítico/Medio/Bajo).
* **📍 Geolocalización Avanzada:** Rastreo detallado de IP, Ciudad, País, ISP y Organización del servidor.
* **🔍 Inteligencia SSL & Fingerprinting:** Extracción de datos del emisor del certificado y detección de banners de software de servidor.
* **📸 Stealth Forensic Capture:** Captura de pantalla en modo Headless con bypass de certificados SSL inválidos para análisis de Phishing.
* **📄 Professional Reporting:** Generador de reportes PDF con diseño corporativo, tablas de hallazgos y evidencias enmarcadas.

---

## 🛠️ Instalación y Uso rápido

Optimizado para **Kali Linux** y sistemas basados en Debian.

### 1. Clonar y Configurar
```bash
git clone [https://github.com/albertChOXrX/vErtex-AlBERKoma.git](https://github.com/albertChOXrX/vErtex-AlBERKoma.git)
cd vErtex-AlBERKoma
pip install -r requirements.txt
sudo apt update && sudo apt install firefox-geckodriver -y
python3 vErtex.py
```
## 📊 Flujo de Auditoría vErtex
-Recon: Resolución DNS y validación de IP.

-Scan: Mapeo de puertos y servicios activos.

-Geo: Localización física de la infraestructura.

-Vuln: Análisis de cabeceras de seguridad y huellas digitales.

-Evidence: Captura visual y generación de reporte PDF.

## 📂 Estructura del Proyecto
-vErtex.py: Motor principal de la suite.

-Requirements.txt: Dependencias de Python (requests, fpdf, colorama, selenium, dnspython).

-Evidencia_*.png: Capturas temporales de los sitios analizados.

-VErtex_ULTIMATE_*.pdf: Informes finales de auditoría.

## 🛡️ Estado del Proyecto y Compatibilidad

![Estado](https://img.shields.io/badge/Estado-Activo-brightgreen?style=for-the-badge&logo=github)
![Version](https://img.shields.io/badge/Versión-4.0%20Titanium-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10+-yellow?style=for-the-badge&logo=python)
![OS](https://img.shields.io/badge/OS-Kali%20Linux%20|%20Linux-lightgrey?style=for-the-badge&logo=kali-linux)

---

## 🤝 Contribuciones
¡Las sugerencias y mejoras son bienvenidas! Si encuentras un error o quieres añadir una función, abre un **Issue** o envía un **Pull Request**.

## 👤 Autor
Desarrollado por [albertChOXrX](https://github.com/albertChOXrX)

---
**¡Gracias por usar vErtex!** Si te gusta este proyecto, dale una ⭐ en GitHub.
## ⚠️ Aviso Legal
Este software es para fines educativos y auditoría ética. El autor no se hace responsable del uso indebido.
