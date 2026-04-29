import json
import os
import sqlite3
from datetime import datetime
import config

class DBManager:
    def __init__(self):
        self.db_path = config.DB_PATH
        self.log_dir = config.LOG_DIR
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table for hardware metrics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu REAL,
                memory REAL,
                sessions INTEGER
            )
        ''')
        
        # Table for forensic logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log_id TEXT,
                type TEXT,
                action TEXT,
                src_addr TEXT,
                src_port INTEGER,
                dst_addr TEXT,
                dst_port INTEGER,
                policy_id TEXT,
                service_name TEXT,
                app_name TEXT,
                sent_bytes INTEGER,
                rcvd_bytes INTEGER,
                location TEXT,
                url TEXT,
                browser TEXT,
                msg TEXT
            )
        ''')

        # Table for Multi-WAN stats
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wan_metrics (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                interface_name TEXT,
                ip_addr TEXT,
                status TEXT,
                tx_mb REAL,
                rx_mb REAL
            )
        ''')

        # Table for policy snapshots (to detect changes)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policies (
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                policy_data TEXT
            )
        ''')

        # Table for Authentication/Login events (v7.2.x user-auth)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_time INTEGER UNIQUE,
                log_id TEXT,
                user TEXT,
                src_ip TEXT,
                action TEXT,
                status TEXT,
                reason TEXT,
                ui_interface TEXT,
                msg TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    def save_to_json(self, data_type, data):
        """Saves raw data to a dated folder inside daily_logs.
           Logs are split into utm_logs.json and traffic_logs.json.
        """
        day_folder = datetime.now().strftime("%d%m%Y")
        day_path = os.path.join(self.log_dir, day_folder)
        if not os.path.exists(day_path):
            os.makedirs(day_path)
            
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Map data_type to specific filenames
        files_to_save = {}
        
        if data_type == 'logs':
            utm_data = [item for item in data if item.get('type') == 'utm']
            traffic_data = [item for item in data if item.get('type') != 'utm']
            if utm_data: files_to_save['utm_logs.json'] = utm_data
            if traffic_data: files_to_save['traffic_logs.json'] = traffic_data
        else:
            files_to_save[f"{data_type}.json"] = data if isinstance(data, list) else [data]

        for filename, record_list in files_to_save.items():
            filepath = os.path.join(day_path, filename)
            
            # Read existing data or start fresh
            existing_data = {"logs": [], "wan_stats": [], "login_events": [], "denied_security": []}
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    try:
                        existing_data = json.load(f)
                    except json.JSONDecodeError:
                        pass

            # Standardize records
            for item in record_list:
                item['captured_at'] = timestamp
            
            # If it's a log-type file, we put data under 'logs' key for the sync to see it
            target_key = "logs" if "logs.json" in filename else data_type
            if target_key not in existing_data: existing_data[target_key] = []
            existing_data[target_key].extend(record_list)

            with open(filepath, "w") as f:
                json.dump(existing_data, f, indent=2)
        
        return day_path

    def sync_json_to_sqlite(self, folder_path):
        """Imports data from all JSON files in the daily folder into SQLite."""
        if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
            return

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for filename in os.listdir(folder_path):
            if not filename.endswith(".json"): continue
            
            filepath = os.path.join(folder_path, filename)
            with open(filepath, "r") as f:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    continue
        
            if 'logs' in data:
                for s in data['logs']:
                    cursor.execute('''
                        INSERT INTO logs (timestamp, log_id, type, action, src_addr, src_port, 
                                         dst_addr, dst_port, policy_id, service_name, app_name, 
                                         sent_bytes, rcvd_bytes, location, url, browser, msg)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (s.get('timestamp'), s.get('log_id'), s.get('type'), s.get('action'),
                          s.get('src_addr'), s.get('src_port'), s.get('dst_addr'), s.get('dst_port'),
                          s.get('policy_id'), s.get('service_name'), s.get('app_name'),
                          s.get('sent_bytes'), s.get('rcvd_bytes'), s.get('location', 'Internal'), 
                          s.get('url', 'N/A'), s.get('browser', 'N/A'), s.get('msg')))

            if 'wan_stats' in data:
                for s in data['wan_stats']:
                    cursor.execute('''
                        INSERT INTO wan_metrics (interface_name, ip_addr, status, tx_mb, rx_mb)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (s.get('name'), s.get('ip'), s.get('status'), s.get('tx'), s.get('rx')))

            if 'login_events' in data:
                for s in data['login_events']:
                    cursor.execute('''
                        INSERT OR IGNORE INTO auth_logs (event_time, log_id, user, src_ip, action, status, reason, ui_interface, msg)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (s.get('eventtime'), s.get('logid'), s.get('user'), s.get('srcip'), 
                         s.get('action'), s.get('status'), s.get('reason'), s.get('ui'), s.get('msg')))

        conn.commit()
        conn.close()

    def save_metrics(self, cpu, mem, sess):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO metrics (cpu, memory, sessions) VALUES (?, ?, ?)", (cpu, mem, sess))
        conn.commit()
        conn.close()

    def save_policy_snapshot(self, policy_json):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO policies (policy_data) VALUES (?)", (json.dumps(policy_json),))
        conn.commit()
        conn.close()

    def get_todays_data(self):
        """Fetches all logs and metrics from today for the report."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get logs from last 24h
        cursor.execute("SELECT * FROM logs WHERE timestamp >= datetime('now', '-1 day')")
        logs = [dict(r) for r in cursor.fetchall()]
        
        # Get last 2 policy snapshots to compare
        cursor.execute("SELECT policy_data FROM policies ORDER BY timestamp DESC LIMIT 2")
        snapshots = cursor.fetchall()

        # Get interface metrics from last 24h
        cursor.execute("SELECT * FROM wan_metrics WHERE timestamp >= datetime('now', '-1 day')")
        wan_stats = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        return {"logs": logs, "snapshots": snapshots, "wan_stats": wan_stats}

    def get_auth_logs(self, days=5):
        """Fetches authentication events for the N-day audit."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM auth_logs WHERE timestamp >= datetime('now', '-{days} days') ORDER BY timestamp DESC")
        logs = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return logs
