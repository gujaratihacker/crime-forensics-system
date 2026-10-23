def ensure_awareness_scams_table(conn):
    with conn.cursor() as cursor:
        cursor.execute("""
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
            ) ENGINE=InnoDB
        """)
