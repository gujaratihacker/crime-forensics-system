# Smart Online Crime Reporting, Case Management & Digital Evidence Forensics System

[![Python](https://img.shields.io/badge/Python-3.14+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.3-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=for-the-badge&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?style=for-the-badge&logo=bootstrap&logoColor=white)](https://getbootstrap.com/)
[![Cyber Forensics](https://img.shields.io/badge/Forensics-SHA--256_Vault-0284c7?style=for-the-badge&logo=security&logoColor=white)](#forensic-integrity--hashing-design)
[![AI Engine](https://img.shields.io/badge/CyberShield-AI_Intelligence-10b981?style=for-the-badge&logo=openai&logoColor=white)](#key-ai--interactive-features)

A secure, educational digital platform prototype designed for the **MCA Cyber Security and Forensics** minor project. It simulates how citizens report cybercrimes, upload digital evidence, start livestream broadcasts, and how investigators/admins manage casework life-cycles, maintain an unbroken cryptographic chain of custody, and run forensic validations.

---

> [!WARNING]
> **Academic Demonstration Prototype**: This project is developed exclusively for educational and academic evaluation. It must **NOT** be connected to real police systems, government networks, or emergency responders. It operates only on simulated datasets.

---

## 🌟 Key AI & Interactive Features

### 1. 🛡️ CyberShield AI Scam & Phishing Diagnostic Center
- **Instant Heuristic Scan**: Citizens can paste suspicious SMS messages, WhatsApp forwards, Telegram job offers, or URLs.
- **Scam Probability Meter**: Calculates risk scores (0–100%) with dynamic color-coded urgency gauges.
- **Threat Vector Detection**: Flags brand spoofing (SBI, Paytm, Netflix), fake KYC deactivations, sextortion blackmail, and deceptive TLDs (`.xyz`, `.top`, `.click`).
- **Tactics Breakdown**: Explains psychological manipulation (Manufactured Urgency, Authority Impersonation, False Employment).
- **One-Click Escalation**: Automatically exports detected scam details and suspect contacts directly into the incident complaint form.

### 2. ⚡ Real-Time AI Incident Co-Pilot (Complaint Reporting)
- **Live Threat Urgency Gauge**: Analyzes complaints dynamically as citizens draft them, rating severity from Standard to Critical.
- **Automated Suspect Footprint Extraction**: Automatically parses and tags phone numbers, UPI IDs, email addresses, crypto wallets, and social handles (`@username`).
- **Investigation Readiness Checklist**: Interactively verifies whether essential details (timeframe, UTR, suspect handle, evidence screenshots) are provided.
- **AI Statement Polish & Restructuring**: Formats unstructured or conversational complaints into formal investigative statements with legal sections and clear chronology.

### 3. 💬 Interactive Multilingual Floating Cyber Counselor
- **Floating Assistant**: Accessible across all portal pages.
- **Multilingual Support**: Provides safety guidance in English, हिन्दी (Hindi), and ગુજરાતી (Gujarati).
- **Golden-Hour Protocols**: Guides citizens through emergency account freezes and helpline connections (**1930**).

### 4. 🧠 Investigator AI Case Copilot
- **Modus Operandi (M.O.) Classifier**: Identifies cybercrime attack patterns (e.g., Task-Based Ponzi Scheme, Smishing with APK Dropper, Video Call Sextortion).
- **Statutory Legal Mapping**: Recommends applicable sections under the **Information Technology Act, 2000** (Sec 66, 66C, 66D, 66E, 67) and **Bharatiya Nyaya Sanhita (BNS)** / IPC.
- **Forensic Evidence Checklist**: Alerts investigators to critical requisitions (Bank Nodal Freeze, IPDR/CDR logs, Section 91 CrPC notice).

### 5. 🔐 Forensic Digital Evidence Vault & Chain of Custody
- **SHA-256 Cryptographic Checksums**: Uploaded digital evidence is hashed in 64KB blocks.
- **Tamper Detection**: Investigators can verify file hashes in real time to detect any bit-level modification or spoliation.
- **Chronological Custody Ledger**: Every view, download, verification, or update generates an immutable audit entry.

### 6. 📹 Simulated Live Incident Streaming
- **Browser Camera Feeds**: Stream snapshot frames via base64 JPEGs.
- **Automatic Vaulting**: Records video locally with the `MediaRecorder` API and automatically deposits the `.webm` file into the forensic evidence vault upon conclusion.
- **Intelligence Chat Moderation**: Automoderates witness chatter and enables investigators to promote leads directly to the casework file.

### 7. 🕸️ Suspect Intelligence Network Visualizer
- Uses `vis-network` to generate interactive topological graphs connecting cases, suspect identifiers, and related cross-complaint connections.

---

## 🛠️ Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | HTML5, CSS3, JavaScript (ES6+), Bootstrap 5.3, Bootstrap Icons, Vis-Network |
| **Backend** | Python 3.14+, Flask (Blueprints architecture), Werkzeug |
| **AI Engine** | Local NLP Heuristic Engine, Pattern Tokenizer, Modus Operandi Classifier |
| **Database** | MySQL / MariaDB (PyMySQL connector) |
| **Forensics** | Python `hashlib` (SHA-256), `MediaRecorder` API, EXIF parser |

---

## 🚀 Installation & Local Setup

### Prerequisites
1. **Python 3.14+** installed.
2. **MySQL / MariaDB** running locally on port `3306` (e.g. through XAMPP).

### Setup Instructions

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/minor-project.git
   cd "minor-project"
   ```

2. **Create and activate virtual environment**:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize & Seed the Database**:
   ```bash
   python seed_data.py
   ```
   *Creates the `crime_forensics_db` database, loads `schema.sql`, sets up upload directories, and seeds sample demo data.*

5. **Start the Flask Server**:
   ```bash
   python app.py
   ```

6. **Open in Web Browser**:
   ```text
   http://127.0.0.1:5000
   ```

---

## 🧪 Running the Test Suite

Execute the comprehensive unit and integration test suite:

```powershell
.\.venv\Scripts\python.exe -m unittest tests/test_suite.py
```

All unit tests cover:
- Password security and hashing
- CSRF validation and role authorization
- AI Scam Detector & Threat Heuristics
- AI Live Draft Analyzer & Statement Polish
- Forensic SHA-256 tampering detection
- Audit logging ledger

---

## 👥 Demo Test Accounts

| Role | Username / Email | Password | Scope & Dashboard |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin1` / `admin@forensics.local` | `Admin@123` | System oversight, user promotion, audit logs, moderation queue. |
| **Investigator** | `investigator1` / `investigator1@forensics.local` | `Investigator@123` | Case inspection, AI copilot, evidence hash checks, suspect network. |
| **Citizen 1** | `citizen1` / `citizen1@forensics.local` | `Citizen@123` | Identified reporting, live AI copilot, case timeline tracking. |
| **Citizen 2** | `citizen2` / `citizen2@forensics.local` | `Citizen@123` | Anonymous reporting and livestream simulation. |

---

## 🌐 Cloud Deployment (Railway + Netlify)

- **Railway Backend**: Deploy the repository with the included `Procfile` (`web: gunicorn app:app`). Map `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, and `SECRET_KEY` in Railway Variables.
- **Netlify Proxy**: Deploy front proxy via `netlify.toml` with `FLASK_BACKEND_URL` configured.

---

## 📄 License & Attribution
Developed for educational research and coursework in **MCA Cyber Security and Digital Forensics**.
