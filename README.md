# 🛡️ PhishGuard Web

Welcome to **PhishGuard Web**, a comprehensive, multi-stage cybersecurity tool designed to analyze and detect phishing threats across URLs, raw text, QR codes, and audio speech. 

Built with a strict **Zero-CDN, native front-end** and a robust **dual-layer machine learning backend**, PhishGuard provides real-time threat intelligence directly to your browser.

---

## 📑 Table of Contents
- [Architecture Overview](#-architecture-overview)
- [Key Features](#-key-features)
- [Prerequisites](#-prerequisites)
- [Quick Start Guide](#-quick-start-guide)
- [How to Use the Tools](#-how-to-use-the-tools)
- [Configuration (VirusTotal)](#-configuration-virustotal)

---

## 🏗️ Architecture Overview

PhishGuard Web utilizes a microservice architecture to filter incoming threats through two distinct layers before presenting the results in the Chrome Extension UI:

1. **Frontend (Chrome Extension):** A strict, secure UI built with pure HTML/CSS and Vanilla JavaScript. Leverages native browser APIs for advanced hardware scanning without third-party libraries.
2. **Stage 1: Python ML Model (`/model/app.py`):** A FastAPI backend running a pre-trained Scikit-Learn `joblib` model. Extracts deep URL features (Shannon entropy, TLD heuristics, tracking beacons) to calculate an exact threat probability.
3. **Stage 2: Node.js Orchestrator (`server.js`):** A middleware pipeline that routes data to the Python ML model. If the ML model flags a threat, the Orchestrator automatically escalates the payload to the **VirusTotal v3 API** for global vendor consensus.

---

## ✨ Key Features

### 💻 Frontend (The Chrome Extension)
*   **🌐 Analyze Open Tabs:** Instantly queries all open browser tabs and bulk-analyzes them for phishing threats.
*   **📷 Native QR Scanner:** Upload QR code images directly. Decodes using Chrome's native `BarcodeDetector` API.
*   **🎙️ Native Audio Scanner:** Listens for malicious/scam language via the microphone using native `webkitSpeechRecognition`.
*   **📝 Text & Payload Analysis:** Paste suspicious emails, SMS messages, or URLs for deep-scan processing.
*   **🧠 Model Selection:** Dropdown integration allowing you to toggle the active threat-detection model context.

### ⚙️ Backend (The Orchestrator & ML Engine)
*   **Dual-Stage Filtering:** Data hits the local machine learning model first, and optionally escalates to VirusTotal if suspicious.
*   **Feature Extraction:** Native Python algorithms extract subdomain counts, hyphen ratios, and suspicious keyword cross-referencing.
*   **Zero-Dependency Pipeline:** The Node.js orchestrator uses standard native modules to maximize execution speed and security.

---

## 📦 Prerequisites

Ensure your system has the following installed before starting:
*   **Node.js** (v18+ recommended for native `fetch()` support)
*   **Python 3.8+**
*   **Google Chrome** (For installing the extension)

---

## 🚀 Quick Start Guide

### 1. Install Python Dependencies
The FastAPI model requires specific data science libraries. Navigate to the model folder (located just outside this repository) and install them:
```bash
cd ../model
pip install fastapi uvicorn scikit-learn pandas tldextract joblib pydantic
cd ../HTH180CS15
```

### 2. Boot the Servers
We have provided a unified startup script to boot both the Node.js orchestrator and the Python ML model simultaneously:
```bash
./start_app.sh
```
*(Press `CTRL+C` at any time to cleanly shut down both servers).*

### 3. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** using the toggle in the top right corner.
3. Click **Load unpacked** in the top left.
4. Select the main `HTH180CS15` project folder.
5. Click the PhishGuard puzzle icon in your Chrome toolbar to open the application!

---

## 🛠️ How to Use the Tools

*   **URL Search:** Type any web address into the search bar and press `Enter` to analyze it.
*   **Text Analysis:** Paste an entire suspicious email or message into the text area and click **Analyze Text**.
*   **Scan QR Image:** Click the button to open your file explorer. Select a screenshot of a QR code. The app will decode it locally and send the hidden URL to the backend.
*   **Listen & Analyze Audio:** Click to activate your microphone. Speak (or play) a recording of a suspected scam call. Click again to stop, transcribe, and analyze the speech pattern.

---

## 🔐 Configuration (VirusTotal)

To unlock Stage 2 of the backend pipeline, you must provide a VirusTotal API key. If no key is provided, the system seamlessly falls back to relying purely on your local ML model.

To enable VirusTotal, modify the `start_app.sh` script to include your key:
```bash
# Inside start_app.sh
export VIRUSTOTAL_API_KEY="insert_your_actual_api_key_here"
```
Once added, restart the servers. The orchestrator will now query the global VirusTotal database for consensus whenever the ML model detects high-risk patterns.