import sqlite3
import logging

# Configure logging to write to a file
logging.basicConfig(filename='debug.log', level=logging.DEBUG, format='%(asctime)s %(message)s')

def init_db():
    conn = sqlite3.connect('network_traffic.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS firewall_logs (
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
            attack_type TEXT,
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
            service TEXT,
            logged_by_isolation_forest BOOLEAN
        )
    ''')
    conn.commit()
    conn.close()
    logging.info("Database initialized and tables created if they did not exist.")
    print("Database initialized and tables created if they did not exist.")

def log_packet(src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output, attack_type, inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service, logged_by_isolation_forest):
    if src_ip == "N/A" or dst_ip == "N/A" or protocol == "N/A":
        logging.debug(f"Invalid packet data for logging: SRC {src_ip}, DST {dst_ip}, PROTOCOL {protocol}.")
        print(f"Invalid packet data for logging: SRC {src_ip}, DST {dst_ip}, PROTOCOL {protocol}.")
        return None
    try:
        conn = sqlite3.connect('network_traffic.db')
        c = conn.cursor()
        logging.debug("Database connection established.")
        print("Database connection established.")
        logging.debug(f"Logging packet: SRC {src_ip}, DST {dst_ip}, SPORT {src_port}, DPORT {dst_port}, PROTOCOL {protocol}, LENGTH {length}")
        query = '''
            INSERT INTO firewall_logs (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output, attack_type, inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service, logged_by_isolation_forest)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        '''
        params = (src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload, packet_details, malicious, confidence, model_output, attack_type, inter_arrival_time, byte_ratio, sbytes, dur, dbytes, state, sttl, dttl, service, logged_by_isolation_forest)
        c.execute(query, params)
        conn.commit()
        log_id = c.lastrowid
        logging.debug(f"Packet logged successfully. Log ID: {log_id}")
        print(f"Packet logged successfully. Log ID: {log_id}")
        return log_id
    except sqlite3.Error as e:
        logging.debug(f"Database error: {e}")
        print(f"Database error: {e}")
    except Exception as e:
        logging.debug(f"Error logging packet: {e}")
        print(f"Error logging packet: {e}")
    finally:
        if conn:
            conn.close()
            logging.debug("Database connection closed.")
            print("Database connection closed.")

# Initialize the database
init_db()

# Test logging a packet
log_id = log_packet(
    src_ip="192.168.1.1",
    dst_ip="192.168.1.2",
    src_port=12345,
    dst_port=80,
    protocol="TCP",
    length=100,
    flags="S",
    payload="test_payload",
    packet_details="test_packet_details",
    malicious=False,
    confidence=0.0,
    model_output="None",
    attack_type="None",
    inter_arrival_time=0.0,
    byte_ratio=1.0,
    sbytes=100,
    dur=1.0,
    dbytes=100,
    state="SYN",
    sttl=64,
    dttl=64,
    service="HTTP",
    logged_by_isolation_forest=True
)

print(f"Log ID: {log_id}")
