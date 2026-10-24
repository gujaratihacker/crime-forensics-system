# Smart Online Crime Reporting, Case Management & Digital Evidence Forensics System

A secure, educational digital platform prototype designed for the **MCA Cyber Security and Forensics** minor project. It simulates how citizens can report cybercrimes, upload digital evidence, start livestream broadcasts, and how investigators/admins manage the case life-cycles, maintain chain of custody, and run forensic validations.

---

## 1. Project Overview & Intent
This is an **academic demonstration prototype**. 
> [!WARNING]
> It must **NOT** be connected to real police, government databases, or real-world emergency responders. It utilizes only fictional testing datasets.

---

## 2. Key Features

- **Multi-Role Access Control (RBAC)**: Custom Flask-session-based authorization separating Citizens, Investigators, and Administrators.
- **Admin User Management**: Administrators can list accounts, create users with roles, promote or demote accounts, and remove accounts when doing so will not erase investigation history or assigned casework.
- **Identified & Anonymous Reporting**: Allows citizens to toggle anonymity. When active, citizen profiling information (name, contacts, email, exact location) is isolated and masked, displaying as **Anonymous Reporter** on public feeds.
- **AI-Assisted Complaint Analysis**: A modular, regex and keyword-based local NLP script that auto-categorizes reports, estimates priority levels, detects missing information, suggests evidence types, and parses suspect indicators (emails, UPI IDs, phone numbers, URLs).
- **Digital Evidence Vault**: Secure evidence uploads hashed with SHA-256 check values.
- **Forensic Integrity Verification**: A validation panel letting investigators recalculate file SHA-256 hashes against database logs to detect file tampering.
- **Chronological Chain of Custody**: Ledgers documenting every transaction on evidence files (uploading, accessing, verifying, downloading) shown on the case timeline.
- **Simulated Live Streaming**:
  - Citizens start streams via browser cameras.
  - Snapshot frames are posted via base64 JPEGs every 1s.
  - Viewers poll the snapshot feed to watch in near real-time.
  - Browser records the feed locally via `MediaRecorder` API, auto-uploading the WebM file to the Forensic Vault upon stream termination.
- **Community Chat Intel**: Live stream commentators provide witnessed details. Suspect phone numbers or abusive keywords are auto-moderated and flagged.
- **Investigation Lead System**: Investigators can review community chatter and promote witness comments into formal investigation leads.
- **Suspect Intelligence network map**: Uses `vis-network` (via CDN) to render interactive graphs connecting cases, suspect profiles, specific identifiers, and matching duplicate cases.
- **Case Tracking Timeline**: Explainable step-by-step progress tracking for citizen complaints.
- **Full Security Audit Logs**: Centralized, unmodifiable ledger capturing all system changes, logged by user credentials and source IP.

---

## 3. Technology Stack
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5, Bootstrap Icons, Chart.js, Vis-Network (CDN).
- **Backend**: Python 3.14+, Flask.
- **Database**: MySQL / MariaDB (from local XAMPP setup).
- **Forensics & Hashing**: Python `hashlib` (SHA-256), `MediaRecorder` API.

---

## 4. Installation & Database Setup

### Prerequisites
1. **Python 3** installed.
2. **XAMPP** (or MySQL server running locally on port `3306`).
3. Ensure MySQL is running on XAMPP (default config: Host `localhost`, User `root`, no password).

### Setup Directory
1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd "d:\MCA\minor project"
   ```

2. Install Python requirements:
   ```bash
   pip install -r requirements.txt
   ```

3. Set a private Flask session key in PowerShell before starting the app:
   ```powershell
   $env:SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
   ```
   If you omit this, the app generates a temporary key at startup and logged-in
   sessions will be invalidated when the app restarts. Do not commit your key.

4. Setup & Seed Database:
   Run the seed script. It automatically connects to your local MySQL server, creates the database `crime_forensics_db`, initializes the tables, creates static/uploads directories, and populates the tables with demo cases:
   ```bash
   python seed_data.py
   ```

---

## 5. Running the Application

1. Start the Flask server:
   ```bash
   python app.py
   ```
2. Open your web browser and navigate to:
   ```text
   http://127.0.0.1:5000
   ```

---

## 6. Deploying with Netlify

Netlify provides the public HTTPS URL and proxies requests to this project's
Flask backend. The Flask app and MySQL/MariaDB database must also be deployed
to a Python host; Netlify does not run this project as a persistent Flask
server.

1. Deploy the repository to a Python web host that supports Gunicorn and
   persistent storage. The included `Procfile` starts the Flask app using the
   host's `PORT` environment variable.
2. Provision an empty MySQL/MariaDB database reachable by the Flask service,
   then configure `DB_HOST`, `DB_USER`, `DB_PASSWORD`, and `DB_NAME` on the
   backend. Also set `SECRET_KEY` to a long, random secret and
   `SESSION_COOKIE_SECURE=true`. Never use the demo credentials for a public
   deployment.
3. Attach persistent storage at the app's `uploads` directory. Evidence,
   verification files, missing-person images, live snapshots, and recordings
   are stored there and will otherwise be lost when the backend restarts.
4. Initialize a **new, empty demo database** once with `python seed_data.py`.
   This script drops and recreates project tables each time it runs. Do not run
   it against a database containing data you need.
5. In Netlify, import this GitHub repository and add the `FLASK_BACKEND_URL`
   environment variable containing the backend's public HTTPS origin, such as
   `https://your-app.example.com` (no path). The root `netlify.toml` invokes
   `scripts/build_netlify.py`, which generates a catch-all proxy rewrite.
6. Deploy the Netlify site. If the backend URL changes, update the Netlify
   environment variable and redeploy.

Netlify's proxy rewrites time out after 26 seconds. Large evidence/video
uploads or long-running requests may need direct backend or object-storage
URLs to work reliably. This is still an academic demonstration system: use
fictional test data only; do not connect it to real emergency responders or
government databases.

## 7. Test Accounts (Demo Dataset)

Use these credentials to test the various dashboards:

| Role | Username / Email | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Admin** | `admin1` or `admin@forensics.local` | `Admin@123` | System oversight, user assignments, comment moderation. |
| **Investigator** | `investigator1` or `investigator1@forensics.local` | `Investigator@123` | Case inspection, notes ledger, evidence checking, suspect map. |
| **Citizen 1** | `citizen1` or `citizen1@forensics.local` | `Citizen@123` | Identified complaint reporting, case progress tracking. |
| **Citizen 2** | `citizen2` or `citizen2@forensics.local` | `Citizen@123` | Anonymous complaint and livestream simulation. |

---

## 8. Forensic Integrity & Hashing Design

- **SHA-256 Calculation**: Files uploaded to `uploads/evidence/` are processed in 64KB chunks to prevent RAM exhaustion. A 64-character SHA-256 string is generated and logged in MySQL.
- **Custody Chain**:
  - `UPLOADED`: Generated on initial file preservation.
  - `ACCESSED`: Logged whenever an investigator opens or downloads the file.
  - `VERIFIED`: Logged on successful hash checks.
  - `VERIFY_FAILED`: Logged if file checksums do not match, signaling data tampering.
- **Audit Logs**: Unmodifiable logs that record operations alongside user IDs, timestamps, and client IP addresses.

---

## 9. Limitations & Future Scope
- **WebRTC Signalling**: This system uses periodic JPEG polling as a robust local alternative to complex WebRTC STUN/TURN servers. Real production implementations would require signalling engines.
- **Local Hashing**: Hashing happens on the backend. True forensics could add client-side hashing to verify that files are not tampered with during transmission.
- **Mock AI Service**: The AI recommendations are rule-based. Future versions could integrate actual LLMs or BERT models via API calls.
