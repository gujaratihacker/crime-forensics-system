-- Smart Online Crime Reporting, Case Management & Digital Evidence Forensics System
-- Database Schema

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    phone VARCHAR(20) NOT NULL,
    fullname VARCHAR(100) NOT NULL,
    role ENUM('citizen', 'investigator', 'admin') DEFAULT 'citizen',
    verification_doc_type VARCHAR(50) NULL,
    verification_doc_path VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_role (role)
) ENGINE=InnoDB;

-- 2. Complaints Table
CREATE TABLE IF NOT EXISTS complaints (
    id VARCHAR(20) PRIMARY KEY,
    citizen_id INT NULL,
    category VARCHAR(50) NOT NULL,
    incident_date DATE NOT NULL,
    incident_time TIME NOT NULL,
    location VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    victim_info TEXT,
    suspect_info TEXT,
    contact_indicators VARCHAR(255),
    financial_loss DECIMAL(15, 2) DEFAULT 0.00,
    additional_info TEXT,
    reporting_mode ENUM('identified', 'anonymous') DEFAULT 'identified',
    status ENUM('submitted', 'under_review', 'accepted', 'rejected') DEFAULT 'submitted',
    priority ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'LOW',
    priority_reason TEXT,
    ai_category VARCHAR(50),
    ai_priority VARCHAR(20),
    ai_missing_info TEXT,
    ai_recommended_evidence TEXT,
    ai_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (citizen_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_complaint_status (status),
    INDEX idx_complaint_priority (priority)
) ENGINE=InnoDB;

-- 3. Cases Table
CREATE TABLE IF NOT EXISTS cases (
    id VARCHAR(20) PRIMARY KEY,
    complaint_id VARCHAR(20) NOT NULL UNIQUE,
    investigator_id INT NULL,
    status ENUM('assigned', 'under_investigation', 'evidence_analysis', 'final_review', 'resolved', 'closed') DEFAULT 'assigned',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_case_status (status)
) ENGINE=InnoDB;

-- 4. Investigators Table
CREATE TABLE IF NOT EXISTS investigators (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNIQUE NOT NULL,
    rank VARCHAR(50) DEFAULT 'Junior Detective',
    department VARCHAR(100) DEFAULT 'Cyber Crime Cell',
    assigned_cases_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 5. Evidence Table
CREATE TABLE IF NOT EXISTS evidence (
    id VARCHAR(20) PRIMARY KEY,
    case_id VARCHAR(20) NULL,
    complaint_id VARCHAR(20) NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_type VARCHAR(50) NOT NULL,
    file_size INT NOT NULL,
    sha256_hash VARCHAR(64) NOT NULL,
    upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INT NULL,
    evidence_source ENUM('citizen', 'viewer', 'livestream') DEFAULT 'citizen',
    status ENUM('potential', 'verified', 'failed_integrity') DEFAULT 'potential',
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE SET NULL,
    FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE SET NULL,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_evidence_sha (sha256_hash)
) ENGINE=InnoDB;

-- 6. Evidence Access Logs Table
CREATE TABLE IF NOT EXISTS evidence_access_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id VARCHAR(20) NOT NULL,
    user_id INT NOT NULL,
    action ENUM('viewed', 'downloaded') DEFAULT 'viewed',
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 7. Chain of Custody Table
CREATE TABLE IF NOT EXISTS chain_of_custody (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id VARCHAR(20) NOT NULL,
    user_id INT NULL,
    action VARCHAR(50) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT NOT NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 8. Investigation Notes Table
CREATE TABLE IF NOT EXISTS investigation_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(20) NOT NULL,
    investigator_id INT NOT NULL,
    note_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (investigator_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS case_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(20) NOT NULL,
    sender_id INT NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_case_messages_case_created (case_id, created_at)
) ENGINE=InnoDB;

-- 9. Case Updates (Timeline) Table
CREATE TABLE IF NOT EXISTS case_updates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(20) NOT NULL,
    status VARCHAR(50) NOT NULL,
    update_message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 10. Suspects Table
CREATE TABLE IF NOT EXISTS suspects (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(20) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 11. Suspect Identifiers Table
CREATE TABLE IF NOT EXISTS suspect_identifiers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    suspect_id INT NOT NULL,
    identifier_type ENUM('phone', 'email', 'upi', 'username', 'url', 'transaction_id') NOT NULL,
    identifier_value VARCHAR(255) NOT NULL,
    FOREIGN KEY (suspect_id) REFERENCES suspects(id) ON DELETE CASCADE,
    INDEX idx_identifier (identifier_type, identifier_value)
) ENGINE=InnoDB;

-- 12. Related Cases Table
CREATE TABLE IF NOT EXISTS related_cases (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id_1 VARCHAR(20) NOT NULL,
    case_id_2 VARCHAR(20) NOT NULL,
    common_identifier_type VARCHAR(50) NOT NULL,
    common_identifier_value VARCHAR(255) NOT NULL,
    status ENUM('potential', 'confirmed', 'dismissed') DEFAULT 'potential',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id_1) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (case_id_2) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 13. Live Incidents Table
CREATE TABLE IF NOT EXISTS live_incidents (
    id VARCHAR(20) PRIMARY KEY,
    reporter_id INT NULL,
    category VARCHAR(50) NOT NULL,
    location_approx VARCHAR(100) NOT NULL,
    status ENUM('active', 'completed') DEFAULT 'active',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP NULL,
    reporting_mode ENUM('identified', 'anonymous') DEFAULT 'identified',
    viewer_count INT DEFAULT 0,
    saved_video_evidence_id VARCHAR(20) NULL,
    description TEXT,
    FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 14. Live Viewers Table
CREATE TABLE IF NOT EXISTS live_viewers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    live_incident_id VARCHAR(20) NOT NULL,
    session_id VARCHAR(100) NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (live_incident_id) REFERENCES live_incidents(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 15. Comments Table
CREATE TABLE IF NOT EXISTS comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    live_incident_id VARCHAR(20) NOT NULL,
    user_id INT NULL,
    username_display VARCHAR(100) NOT NULL,
    comment_type ENUM('witness', 'info', 'location', 'evidence', 'pre-stream', 'correction', 'other') DEFAULT 'info',
    comment_text TEXT NOT NULL,
    is_flagged TINYINT(1) DEFAULT 0,
    moderation_status ENUM('pending', 'approved', 'hidden') DEFAULT 'approved',
    proof_stored_filename VARCHAR(255) NULL,
    proof_original_filename VARCHAR(255) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (live_incident_id) REFERENCES live_incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 16. Comment Flags Table
CREATE TABLE IF NOT EXISTS comment_flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    comment_id INT NOT NULL,
    flagged_by INT NULL,
    reason VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (comment_id) REFERENCES comments(id) ON DELETE CASCADE,
    FOREIGN KEY (flagged_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 17. Investigation Leads Table
CREATE TABLE IF NOT EXISTS investigation_leads (
    id VARCHAR(20) PRIMARY KEY,
    case_id VARCHAR(20) NOT NULL,
    source_comment_id INT NOT NULL,
    created_by INT NOT NULL,
    status ENUM('new', 'under_review', 'verified', 'rejected', 'converted', 'closed') DEFAULT 'new',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (source_comment_id) REFERENCES comments(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- 18. Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    case_id VARCHAR(20) NULL,
    evidence_id VARCHAR(20) NULL,
    live_incident_id VARCHAR(20) NULL,
    ip_address VARCHAR(45) NOT NULL,
    description TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 19. Schema Alterations for Livestream Evidence
ALTER TABLE evidence ADD COLUMN live_incident_id VARCHAR(20) NULL;
ALTER TABLE evidence ADD CONSTRAINT fk_evidence_live FOREIGN KEY (live_incident_id) REFERENCES live_incidents(id) ON DELETE SET NULL;

-- 20. Missing Persons Tables
CREATE TABLE IF NOT EXISTS missing_persons (
    id VARCHAR(20) PRIMARY KEY,
    citizen_id INT NULL,
    fullname VARCHAR(100) NOT NULL,
    age INT NOT NULL,
    gender VARCHAR(20) NOT NULL,
    contact_phone VARCHAR(20) NOT NULL,
    last_seen_date DATE NOT NULL,
    last_seen_location VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    photo_path VARCHAR(255) NULL,
    status ENUM('missing', 'found') DEFAULT 'missing',
    found_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (citizen_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS missing_person_comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    missing_person_id VARCHAR(20) NOT NULL,
    user_id INT NULL,
    username_display VARCHAR(100) NOT NULL,
    last_seen_location VARCHAR(255) NULL,
    last_seen_date DATE NULL,
    identification_details TEXT NULL,
    comment_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (missing_person_id) REFERENCES missing_persons(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- 22. Social Media Complaints Metadata Table
CREATE TABLE IF NOT EXISTS social_media_complaints (
    complaint_id VARCHAR(20) PRIMARY KEY,
    platform VARCHAR(50) NOT NULL,
    crime_type VARCHAR(100) NOT NULL,
    profile_url VARCHAR(500) NOT NULL,
    FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS awareness_scams (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(120) NOT NULL,
    summary TEXT NOT NULL,
    warning_signs TEXT NOT NULL,
    safety_advice TEXT NOT NULL,
    icon VARCHAR(40) NOT NULL DEFAULT 'bi-shield-exclamation',
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_awareness_scams_updated (updated_at)
) ENGINE=InnoDB;
