// initDatabase.mjs
import sqlite3 from 'sqlite3';
import path from 'path';

function initDb() {
    const dbPath = path.join(process.cwd(), 'network_traffic.db');
    const db = new sqlite3.Database(dbPath);

    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS firewall_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            malicious BOOLEAN,
            confidence REAL,
            model_output TEXT,
            length INTEGER,
            flags TEXT,
            payload TEXT,
            packet_details TEXT,
            inter_arrival_time REAL,
            byte_ratio REAL,
            sbytes INTEGER,
            dur REAL,
            dbytes INTEGER,
            state TEXT,
            sttl INTEGER,
            dttl INTEGER,
            service TEXT
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER,
            notified BOOLEAN DEFAULT 0,
            notification_timestamp DATETIME,
            acknowledged BOOLEAN DEFAULT 0,
            FOREIGN KEY (log_id) REFERENCES firewall_logs (id)
        )`);
        db.run(`
            CREATE TABLE IF NOT EXISTS securityactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                automaticThreatResponse BOOLEAN,
                updateTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                selectedOption TEXT,
                isActive BOOLEAN
            )
        `);
        // Create notifications table if it doesn't exist
        db.run(`
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER,
                notified INTEGER,
                acknowledged INTEGER,
                timestamp TEXT,
                FOREIGN KEY(log_id) REFERENCES firewall_logs(id)
            )
        `);

        // Create securityactions table if it doesn't exist
        db.run(`
            CREATE TABLE IF NOT EXISTS securityactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                automaticThreatResponse BOOLEAN,
                selectedOption TEXT,
                isActive BOOLEAN,
                updateTime TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create whitelist table if it doesn't exist
        db.run(`
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE
            )
        `);
    });

    db.close();
    console.log('Database initialized and tables created if they did not exist.');
}

export { initDb };
