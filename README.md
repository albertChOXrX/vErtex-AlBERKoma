
# 🛡️ vErtex v6.0 - Enterprise Security Suite

[![Version](https://img.shields.io/badge/version-6.0-cyan?style=for-the-badge&logo=python)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
[![Status](https://img.shields.io/badge/status-active-green?style=for-the-badge)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
[![License](https://img.shields.io/badge/license-MIT-red?style=for-the-badge)](https://github.com/albertChOXrX/vErtex-AlBERKoma/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python)](https://www.python.org/)

**vErtex** es una suite de auditoría de seguridad automatizada de nivel empresarial desarrollada por **albertChOXrX**. Consolidando reconocimiento (OSINT), análisis de infraestructura, detección de vulnerabilidades y análisis de malware en un solo reporte profesional.

[🚀 Instalación](#-instalación-y-uso) | [📖 Documentación](docs/) | [📊 Changelog](CHANGELOG.md) | [🐛 Reportar Issues](https://github.com/albertChOXrX/vErtex-AlBERKoma/issues)

---

## 🆕 ¿Qué hay de nuevo en v6.0?

| Característica | v4.2 | v6.0 Enterprise | Mejora |
|----------------|------|-----------------|--------|
| **Líneas de Código** | 180 | 1,977 | ![](https://img.shields.io/badge/+998%25-success) |
| **Módulos de Seguridad** | 4 | 12 | ![](https://img.shields.io/badge/+200%25-success) |
| **Puertos Escaneables** | 4 | 65,535 | ![](https://img.shields.io/badge/+1,638,275%25-success) |
| **Detección CMS** | ❌ | ✅ 12+ | ![](https://img.shields.io/badge/NEW-blue) |
| **Detección WAF** | ❌ | ✅ 20+ | ![](https://img.shields.io/badge/NEW-blue) |
| **OWASP Top 10 Scanner** | ❌ | ✅ Completo | ![](https://img.shields.io/badge/NEW-blue) |
| **API Discovery** | ❌ | ✅ 15+ endpoints | ![](https://img.shields.io/badge/NEW-blue) |
| **JavaScript Security** | ❌ | ✅ Análisis completo | ![](https://img.shields.io/badge/NEW-blue) |
| **OSINT Integration** | ❌ | ✅ VT + Shodan | ![](https://img.shields.io/badge/NEW-blue) |
| **Security Scoring** | ❌ | ✅ 0-100 | ![](https://img.shields.io/badge/NEW-blue) |

---

## 📈 Historial de Versiones

| Versión | Release | Banner | Descripción |
| --- | --- | --- | --- |
| **v6.0** | 2026-02-14 | ![v6.0](https://img.shields.io/badge/v6.0-ENTERPRISE_EDITION-cyan) | **12 módulos** · OWASP Scanner · WAF Detection · Professional Reports |
| **v4.2** | 2024-XX-XX | ![v4.2](https://img.shields.io/badge/v4.2-GUARDIAN_UPDATE-cyan) | Malware Engine + Vulnerability Matrix + PDF Fix |
| **v4.1** | 2024-XX-XX | ![v4.1](https://img.shields.io/badge/v4.1-INTELLIGENCE-blue) | Geolocalización + Reportes PDF iniciales |
| **v3.0** | 2024-XX-XX | ![v3.0](https://img.shields.io/badge/v3.0-NETWORK_CORE-yellow) | Escaneo de puertos avanzado y DNS |
| **v2.0** | 2024-XX-XX | ![v2.0](https://img.shields.io/badge/v2.0-DISCOVERY-orange) | Manejo de excepciones y Auto-Banner |

---

## 🚀 Características Principales

### 🔍 Módulos de Seguridad (12)

<table>
<tr>
<td width="50%">

#### 🌐 Network & Infrastructure
[![Network](https://img.shields.io/badge/Network_Scan-Active-blue)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Resolución IP y DNS reverso
- Escaneo de puertos (1-65,535)
- Detección de servicios
- GeoIP & ISP detection
- Análisis WHOIS

#### 🔐 SSL/TLS Security
[![SSL](https://img.shields.io/badge/SSL_Analysis-Enabled-green)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Validación de certificados
- Análisis de protocolos (TLS 1.0-1.3)
- Detección de cifrados débiles
- Certificate Transparency logs
- Alertas de expiración

#### 🛡️ Web Application Security
[![WebSec](https://img.shields.io/badge/Web_Security-Advanced-brightgreen)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Detección CMS (12+ plataformas)
- 8 security headers
- Análisis de cookies
- WAF detection (20+ firewalls)
- Technology fingerprinting

#### 🦠 Malware & Threat Analysis
[![Malware](https://img.shields.io/badge/Malware_Scan-Enabled-brightgreen)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Cryptojacking detection
- Código ofuscado
- Redirects maliciosos
- Hidden iframes
- Phishing indicators

</td>
<td width="50%">

#### 🌍 DNS Security Analysis
[![DNS](https://img.shields.io/badge/DNS_Security-Complete-blueviolet)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Todos los registros DNS
- DNSSEC verification
- SPF/DMARC/DKIM analysis
- CAA records
- Email security

#### ⚠️ OWASP Top 10 Scanner
[![OWASP](https://img.shields.io/badge/OWASP-Top_10-red)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Broken Access Control
- Cryptographic Failures
- Injection (XSS, SQLi)
- Security Misconfiguration
- Vulnerable Components
- ... y más

#### 🔌 API Discovery
[![API](https://img.shields.io/badge/API_Discovery-Active-orange)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- 15+ common endpoints
- GraphQL detection
- Introspection testing
- API documentation exposure
- robots.txt analysis

#### 🕵️ OSINT & Threat Intel
[![OSINT](https://img.shields.io/badge/OSINT-Integrated-purple)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- VirusTotal integration
- Shodan integration
- Social media presence
- Certificate Transparency
- Subdomain enumeration

</td>
</tr>
</table>

### 📜 JavaScript Security
[![JS](https://img.shields.io/badge/JS_Analysis-Advanced-yellow)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Análisis de archivos JS
- Detección de patrones peligrosos
- Exposición de secretos (API keys, passwords)
- eval() y innerHTML detection

### 💾 Backup File Discovery
[![Backup](https://img.shields.io/badge/Backup_Discovery-15+_Files-red)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- .git directory exposure
- .env files
- Database backups
- Configuration files
- Archive files

### 🗺️ Subdomain Enumeration
[![Subdomain](https://img.shields.io/badge/Subdomain_Enum-28+_Common-lightblue)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- 28 subdominios comunes
- Active DNS resolution
- Certificate Transparency integration

### 📸 Digital Evidence
[![Visual](https://img.shields.io/badge/Capture-Headless_Chrome-lightgrey)](https://github.com/albertChOXrX/vErtex-AlBERKoma)
- Capturas de pantalla automáticas
- Evidencia forense
- Selenium WebDriver integration

---

## 🛠️ Instalación y Uso

### Prerequisitos

```bash
# Ubuntu/Debian/Kali
sudo apt-get update
sudo apt-get install -y python3 python3-pip chromium-browser chromium-chromedriver

# macOS
brew install python3 chromedriver
```

### Instalación Rápida

```bash
# 1. Clonar el repositorio
git clone https://github.com/albertChOXrX/vErtex-AlBERKoma.git
cd vErtex

# 2. Instalar dependencias
pip3 install -r requirements1.txt

# 3. Ejecutar vErtex v6.0
python3 vErtex.py
```

### Uso Básico

```bash
# Iniciar escaneo
python3 vErtex.py

# Seleccionar modo de escaneo:
# 1. Fast     - 2-3 minutos   (Quick check)
# 2. Normal   - 5-10 minutos  (Standard audit) [RECOMENDADO]
# 3. Deep     - 15-30 minutos (Comprehensive)
# 4. Extreme  - 30-60 minutos (Full assessment)

# Ingresar objetivo
Target: https://example.com
```

---

## 📊 Modos de Escaneo

| Modo | Duración | Puertos | Módulos | Uso Recomendado |
|------|----------|---------|---------|-----------------|
| **Fast** | 2-3 min | 2 | Básicos | Quick security check |
| **Normal** | 5-10 min | 18 | Todos | Standard audit ⭐ |
| **Deep** | 15-30 min | 1,024 | Todos + Subdominios | Pre-deployment |
| **Extreme** | 30-60 min | 65,535 | Todos + Completo | Critical systems |

---

## 📸 Screenshots

### Terminal Output
```
╔══════════════════════════════════════════════════════════════╗
║  ██╗   ██╗███████╗██████╗ ████████╗███████╗██╗  ██╗         ║
║  ██║   ██║██╔════╝██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝         ║
║  ██║   ██║█████╗  ██████╔╝   ██║   █████╗   ╚███╔╝          ║
║  ╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══╝   ██╔██╗          ║
║   ╚████╔╝ ███████╗██║  ██║   ██║   ███████╗██╔╝ ██╗         ║
║    ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝  v6.0   ║
╚══════════════════════════════════════════════════════════════╝

[NETWORK     ] ✅ IP Address resolved: 93.184.216.34
[DNS         ] ✅ A Record: 93.184.216.34
[GEO         ] ✅ Location: United States, Los Angeles
[SSL         ] ✅ Certificate valid for 347 days
[CMS         ] ℹ️ Detected: WordPress
[WAF         ] ℹ️ Detected: Cloudflare
[BACKUP      ] 🔴 Found backup file: .git/config

Security Score: 🟢 85/100 (GOOD)
```

### PDF Report
- Executive Summary con Security Score visual
- Vulnerability Matrix categorizada
- Technology Stack detectado
- Recomendaciones priorizadas
- Evidencia visual (screenshots)

---

## 🎯 Casos de Uso

### 🔒 Auditoría de Seguridad
```bash
python3 vertex_v6.py
Modo: Normal
Target: https://mi-empresa.com
Resultado: PDF profesional con hallazgos
```

### 🐛 Bug Bounty Reconnaissance
```bash
python3 vertex_v6.py
Modo: Deep
Target: https://target.com
Focus: APIs, subdominios, backups
```

### ✅ Compliance Check (PCI-DSS, HIPAA)
```bash
python3 vertex_v6.py
Modo: Normal
Target: https://payment-gateway.com
Review: SSL/TLS, headers, cookies
```

### 🎓 Entrenamiento en Ciberseguridad
```bash
python3 vertex_v6.py
Modo: Fast
Target: http://testphp.vulnweb.com
Aprendizaje: OWASP Top 10
```

---

## 📄 Salidas Generadas

### 1. PDF Report
```
vErtex_v6.0_[dominio]_[timestamp].pdf

Contiene:
✓ Executive Summary
✓ Security Score (0-100)
✓ Target Information
✓ Visual Evidence (Screenshot)
✓ Vulnerability Matrix
✓ Technology Stack
✓ Detailed Findings
✓ Security Recommendations
```

### 2. JSON Export
```json
{
  "metadata": {
    "version": "6.0",
    "scan_date": "2026-02-14T15:30:45",
    "target": "https://example.com",
    "scan_mode": "normal"
  },
  "security_score": 85,
  "vulnerabilities": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 3
  },
  "technologies": [...],
  "findings": [...]
}
```

### 3. Screenshot
```
screenshot_[dominio]_[timestamp].png
```

---

## 🔑 Configuración Opcional

### API Keys (Mejora la funcionalidad)

```bash
# VirusTotal (Domain reputation)
export VT_API_KEY="tu_api_key_virustotal"

# Shodan (Infrastructure intelligence)
export SHODAN_API_KEY="tu_api_key_shodan"

# Hunter.io (Email discovery)
export HUNTER_API_KEY="tu_api_key_hunter"
```

O configurarlos interactivamente durante el escaneo.

---

## 📚 Documentación Completa

- 📖 [Manual Completo v6.0](docs/README_v6_ENTERPRISE.md)
- 🚀 [Guía Rápida en Español](docs/GUIA_RAPIDA.md)
- 📊 [Comparativa v4.2 vs v6.0](docs/COMPARATIVA_COMPLETA_v4_v6.md)
- 📝 [Changelog](CHANGELOG.md)
- 🔧 [Solución de Problemas](docs/TROUBLESHOOTING.md)

---

## 🌟 Comparativa Detallada

<details>
<summary><b>🔍 Click para ver la comparativa completa v4.2 → v6.0</b></summary>

### Código Base
- **v4.2**: 180 líneas
- **v6.0**: 1,977 líneas
- **Mejora**: +998%

### Módulos de Seguridad
- **v4.2**: 4 módulos básicos
- **v6.0**: 12 módulos empresariales
- **Mejora**: +200%

### Escaneo de Puertos
- **v4.2**: 4 puertos fijos
- **v6.0**: 2-65,535 puertos configurables
- **Mejora**: +1,638,275%

### Detección de Tecnologías
- **v4.2**: Sin detección CMS
- **v6.0**: 12+ CMS + tecnologías
- **Mejora**: ∞

### WAF Detection
- **v4.2**: No detecta WAFs
- **v6.0**: 20+ WAFs
- **Mejora**: ∞

### Análisis de Vulnerabilidades
- **v4.2**: Checks básicos
- **v6.0**: OWASP Top 10 completo
- **Mejora**: ∞

### Headers de Seguridad
- **v4.2**: 2 headers
- **v6.0**: 8 headers
- **Mejora**: +300%

### Detección de Malware
- **v4.2**: 2 patrones
- **v6.0**: 25+ patrones en 6 categorías
- **Mejora**: +1,150%

### Reportes
- **v4.2**: PDF básico
- **v6.0**: PDF profesional + JSON + Score
- **Mejora**: +200%

### OSINT
- **v4.2**: GeoIP básico
- **v6.0**: VirusTotal + Shodan + Social Media + CT Logs
- **Mejora**: ∞

</details>

---

## 💡 Características Destacadas

### 🎯 Security Scoring System
Puntuación 0-100 basada en:
- Vulnerabilidades críticas detectadas
- Configuración de security headers
- Certificados SSL/TLS
- Exposición de archivos sensibles
- Presencia de WAF
- Configuración de cookies

### 📊 Professional PDF Reports
- Executive summary
- Visual security score
- Color-coded findings
- Prioritized recommendations
- Technology stack analysis
- Visual evidence included

### 🔄 Multiple Scan Modes
Adaptable a diferentes necesidades:
- **Fast**: Quick checks
- **Normal**: Standard audits
- **Deep**: Pre-deployment
- **Extreme**: Critical systems

### 🌐 OSINT Integration
- VirusTotal domain reputation
- Shodan infrastructure intelligence
- Certificate Transparency logs
- Social media presence detection
- Email security validation

---

## ⚠️ Disclaimer Legal

### ⚡ USO EXCLUSIVO AUTORIZADO

Esta herramienta está diseñada para:

✅ **Uso Permitido:**
- Auditorías de seguridad en sistemas propios
- Pentesting con autorización escrita
- Entornos educativos y de práctica
- Evaluaciones de compliance autorizadas

❌ **Uso Prohibido:**
- Acceso no autorizado a sistemas
- Ataques maliciosos
- Violación de términos de servicio
- Cualquier actividad ilegal

**El autor NO se responsabiliza del uso indebido de esta herramienta.**

Siempre obtenga autorización explícita antes de escanear cualquier sistema que no sea de su propiedad.

---

## 🤝 Contribuir

¡Las contribuciones son bienvenidas!

1. Fork el proyecto
2. Crea tu feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la branch (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

### 📋 Áreas de Contribución

- 🐛 Bug fixes
- ✨ Nuevas funcionalidades
- 📖 Mejoras en documentación
- 🌍 Traducciones
- 🧪 Tests unitarios
- 🎨 Mejoras UI/UX

---

## 🗺️ Roadmap v7.0

- [ ] Dashboard web interactivo (Flask/React)
- [ ] Continuous monitoring mode
- [ ] CVE database integration
- [ ] Nuclei template support
- [ ] Docker container
- [ ] REST API
- [ ] Team collaboration features
- [ ] Historical comparison
- [ ] Custom vulnerability plugins
- [ ] Mobile app analysis
- [ ] Cloud security (AWS, Azure, GCP)
- [ ] Blockchain security analysis

---

## 📊 Estadísticas del Proyecto

![GitHub stars](https://img.shields.io/github/stars/albertChOXrX/vErtex-AlBERKoma?style=social)
![GitHub forks](https://img.shields.io/github/forks/albertChOXrX/vErtex-AlBERKoma?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/albertChOXrX/vErtex-AlBERKoma?style=social)
![GitHub issues](https://img.shields.io/github/issues/albertChOXrX/vErtex-AlBERKoma)
![GitHub pull requests](https://img.shields.io/github/issues-pr/albertChOXrX/vErtex-AlBERKoma)

---

## 🏆 Reconocimientos

- OWASP Foundation por los estándares de seguridad
- Comunidad de seguridad open source
- Todos los contribuidores y usuarios
- Testers y reportadores de bugs

---

## 📞 Soporte y Contacto

- 🐛 **Issues**: [GitHub Issues](https://github.com/albertChOXrX/vErtex-AlBERKoma/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/albertChOXrX/vErtex-AlBERKoma/discussions)
- 📧 **Email**: security@vertex.dev
- 🔐 **Security**: Responsible disclosure via email

---

## 👨‍💻 Autor

<table>
<tr>
<td align="center">
<img src="https://github.com/albertChOXrX.png" width="100px;" alt="albertChOXrX"/>
<br />
<sub><b>albertChOXrX</b></sub>
<br />
<a href="https://github.com/albertChOXrX">💻 GitHub</a>
</td>
</tr>
</table>

---

## 🌟 Versiones

- **v6.0** - Enterprise Edition (Actual) 
- **v4.2** - Guardian Update
- **v4.1** - Intelligence
- **v3.0** - Network Core
- **v2.0** - Discovery 

[Ver todas las releases →](https://github.com/albertChOXrX/vErtex-AlBERKoma/releases)

---

## 🎯 Quick Links

- [🚀 Instalación](#-instalación-y-uso)
- [📖 Documentación](docs/)
- [📊 Changelog](CHANGELOG.md)
- [🐛 Reportar Bug](https://github.com/albertChOXrX/vErtex-AlBERKoma/issues/new)
- [💡 Solicitar Feature](https://github.com/albertChOXrX/vErtex-AlBERKoma/issues/new)
- [📚 Wiki](https://github.com/albertChOXrX/vErtex-AlBERKoma/wiki)

---

<div align="center">

### ⭐ Si te gusta vErtex, dale una estrella en GitHub ⭐

### 🔐 Escanea Éticamente. Siempre con Autorización. 🔐

**Desarrollado con ❤️ por albertChOXrX | 2026**

![Footer](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red)
![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python)
![Security](https://img.shields.io/badge/Security-First-green)

</div>
