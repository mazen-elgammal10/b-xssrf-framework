# B-XSSRF v3.0 🛡️

## 📌 Overview
**B-XSSRF** is an **End-to-End Automated Pentesting Framework** designed for analyzing Android applications and detecting critical vulnerabilities such as:

- **SSRF (Server-Side Request Forgery)**
- **Information Leakage**

## 📝 Screenshots

Here is a look at the B-XSSRF interface and its automated workflow:

### 🔹 Main Menu & Automation Options
![Main Menu](screenshots/main_menu.png)

> Note: More screenshots of the scanning and reporting phases will be added soon.
---

## 🚀 Key Features

### 🔹 APK Static Analysis
- Performs APK **Decompilation**
- Extracts **Hardcoded Secrets**, including:
  - API Keys
  - Firebase URLs

### 🔹 Secrets Scraping Engine
- Uses **Regex-based scanning** to identify sensitive data within the source code

### 🔹 Payload Generation
- Generates **Obfuscated Payloads** (SVG/XML)
- Supports **WAF Bypass Techniques**

### 🔹 Network Reconnaissance
- Integrates with **Nmap** for:
  - Port Scanning
  - Service Detection

### 🔹 SSRF Exploitation Engine
- Exploits SSRF vulnerabilities to access **Internal Services**

### 🔹 Full Automation Chain
Executes the entire attack lifecycle automatically:


" Analysis → Payload → Scan → Exploitation → Reporting "


### 🔹 Professional Security Reporting
- Generates a **Detailed Vulnerability Report** including:
  - Key Findings
  - Risk Level
  - Security Recommendations

---

## 🤖 AI Role in B-XSSRF

B-XSSRF integrates intelligent techniques to enhance the penetration testing process.

### 🔹 Intelligent Static Analysis
- Analyzes decompiled code automatically
- Detects hidden or obfuscated sensitive data

### 🔹 Smart Secrets Detection
- Goes beyond basic regex
- Detects:
  - API keys
  - Tokens
  - Hidden endpoints

### 🔹 Context-Aware Payload Generation
- Generates payloads based on target behavior
- Supports WAF-aware payload crafting

### 🔹 Automated Decision Making
- Chooses optimal attack paths during execution
- Focuses on high-risk targets

### 🔹 Enhanced Reporting
- Provides meaningful vulnerability insights
- Highlights risk severity and impact

---

## 🛠️ Architecture

- `unpacker.py` → APK Decompilation (Apktool)
- `scraper.py` → Extract sensitive data (API Keys / URLs)
- `payload_factory.py` → Generate payloads
- `requester.py` → Port scanning + SSRF requests
- `reporter.py` → Generate final report

---

## ⚙️ How It Works (Attack Flow)

1. Input target APK file  
2. Perform **Decompilation**  
3. Extract **Hardcoded Secrets**  
4. Generate **Bypass Payloads**  
5. Execute **Port Scanning** (e.g., 127.0.0.1)  
6. Identify **Open Ports** (e.g., 5000)  
7. Perform **SSRF Exploitation**:


http://127.0.0.1:5000/


8. Access **Internal Services**  
9. Generate a **Detailed Security Report**

---

## 📖 Usage

Run the tool from the root directory:

```bash
python3 main.py
Steps:
Select:
4

(Full Automation Chain)

Enter APK path:
/home/kali/Desktop/DivaApplication.apk

⚠️ Disclaimer

This tool is intended for educational and ethical hacking purposes only.
Use only on systems you have explicit permission to test.
The developer is not responsible for misuse.

👨‍💻 Developer

Mazen Elgammal
Cybersecurity Researcher & Developer
