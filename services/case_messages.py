def ensure_case_messages_table(conn):
    with conn.cursor() as cursor:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS case_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                case_id VARCHAR(20) NOT NULL,
                sender_id INT NOT NULL,
                message TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
                FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_case_messages_case_created (case_id, created_at)
            ) ENGINE=InnoDB
        """)
