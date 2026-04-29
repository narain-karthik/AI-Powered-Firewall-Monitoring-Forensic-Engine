import schedule
import time
import threading
from datetime import datetime
import config
from fgt_client import FortiGateClient
from db_manager import DBManager
from ai_manager import AIManager
from report_manager import ReportManager
from mail_manager import MailManager

class FirewallMonitor:
    def __init__(self):
        self.fgt = FortiGateClient()
        self.db = DBManager()
        self.ai = AIManager()
        self.report = ReportManager(self.ai)
        self.mail = MailManager()
        self.running = True
        self.state_file = ".last_auth_report"
        # Set start time to now so we only notify about NEW events after script start
        self.last_auth_time = int(time.time() * 10**9) # Nano-seconds for FortiGate eventtime

    def poll_traffic_and_web(self):
        """High-frequency poller (1 min) for all active sessions and security blocks."""
        now_str = datetime.now().strftime('%H:%M:%S')
        print(f"[{now_str}] Polling Full Forensic Set (v4/v6/UTM)...")
        all_formatted = []
        
        # 1. Fetch Forward Traffic (v4 and v6)
        for family in ['ipv4', 'ipv6']:
            traffic = self.fgt.get_traffic_logs(count=40 if family == 'ipv4' else 20, family=family)
            if traffic:
                print(f"  + Fetched {len(traffic)} {family.upper()} records.")
                all_formatted.extend([self.fgt.format_forensic_data(s) for s in traffic])

        # 2. Fetch UTM Security Logs (Blocks & Hits)
        security_cats = ['webfilter', 'app-ctrl', 'ips', 'dns', 'virus']
        for cat in security_cats:
            sec_logs = self.fgt.get_memory_logs(cat, count=20)
            if sec_logs:
                print(f"  + Fetched {len(sec_logs)} UTM-{cat} records.")
                all_formatted.extend([self.fgt.format_forensic_data(s) for s in sec_logs])
            
        # 3. Save and Sync
        if all_formatted:
            # Simple deduplication based on log_id to reduce noise in the 1-min poll
            unique_logs = {log['log_id']: log for log in all_formatted}.values()
            json_path = self.db.save_to_json("logs", list(unique_logs))
            self.db.sync_json_to_sqlite(json_path)
            print(f"  => Processed {len(unique_logs)} unique forensic events.")

        # 4. Login Events (Silent collection for 5-Day Audit)
        raw_events = self.fgt.get_event_logs(count=10)
        events = raw_events.get('results', []) if raw_events else []
        if events:
            json_path = self.db.save_to_json("login_events", events)
            self.db.sync_json_to_sqlite(json_path)

    def poll_system_metrics(self):
        """Low-frequency poller (30 min) for hardware health and policies."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Polling System Metrics & WAN status...")
        
        # 1. Hardware Usage
        status = self.fgt.get_system_status()
        if status and 'results' in status:
            res = status['results']
            cpu = res.get('cpu', [{}])[0].get('current', 0) if isinstance(res.get('cpu'), list) else res.get('cpu', {}).get('current', 0)
            mem = res.get('mem', [{}])[0].get('current', 0) if isinstance(res.get('mem'), list) else res.get('mem', {}).get('current', 0)
            sess = res.get('session', [{}])[0].get('count', 0) if isinstance(res.get('session'), list) else res.get('session', {}).get('count', 0)
            self.db.save_metrics(cpu, mem, sess)

        # 2. Dual WAN Stats
        wan_stats = self.fgt.get_wan_stats()
        if wan_stats:
            self.db.save_to_json("wan_stats", list(wan_stats.values()))

        # 3. Policy Snapshot
        policies = self.fgt.get_policy_snapshot()
        if policies:
            self.db.save_policy_snapshot(policies)

        # (Removed old 30m Login Events polling, now handled by 1m real-time alert)

    def generate_daily_report(self):
        """The 5:00 PM IST automated AI report trigger."""
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Triggering Daily AI Report...")
        
        # 1. Gather all today's data from DB
        data = self.db.get_todays_data()
        
        # 2. Run Speed Test
        print("Running Internet Bandwidth Speed Test...")
        speed_data = self.report.run_speedtest()
        
        # 3. Generate AI Summaries
        print("Generating Daily AI Forensic Summary...")
        ai_summary = self.ai.analyze_traffic(data['logs'])

        # 4. Summarize Logins
        cursor = self.fgt.get_event_logs(count=20)
        logins = cursor.get('results', []) if cursor else []
        login_summary = self.ai.summarize_login_activity(logins)

        # 5. Create PDF
        print("Generating PDF Report...")
        pdf_path = self.report.generate_pdf_report(data, speed_data, ai_summary, login_summary, logins)

        # 6. Email PDF
        print(f"Emailing report to {config.RECIPIENT_MAIL}...")
        self.mail.send_report(pdf_path, config.RECIPIENT_MAIL)
        print(f"Report complete: {pdf_path}")

        # 7. Check if 5-Day Auth Audit is due
        self.check_for_auth_audit()

    def check_for_auth_audit(self):
        """Checks if 5 days have passed since the last Auth Audit report."""
        import os
        from datetime import datetime, timedelta
        
        last_date = None
        if os.path.exists(self.state_file):
            with open(self.state_file, "r") as f:
                try:
                    last_date = datetime.strptime(f.read().strip(), "%d%m%Y")
                except: pass
        
        # If never run or 5+ days passed
        if last_date is None or (datetime.now() - last_date).days >= 5:
            print("\n[AUDIT] Triggering 5-Day Authentication Forensic Audit...")
            auth_events = self.db.get_auth_logs(days=5)
            
            if auth_events:
                pdf_path = self.report.generate_auth_audit_pdf(auth_events)
                print(f"  => Audit PDF generated: {pdf_path}")
                self.mail.send_report(pdf_path, config.RECIPIENT_MAIL)
                
                # Update state file
                with open(self.state_file, "w") as f:
                    f.write(datetime.now().strftime("%d%m%Y"))
                print("  => 5-Day Audit completed and emailed.")
            else:
                print("  => No auth events found for audit cycle.")

    def run(self):
        print("--- AI POWERED FIREWALL MONITORING STARTED ---")
        print(f"Traffic Logging: Every 1 Minute")
        print(f"System Metrics: Every 30 Minutes")
        
        # Immediate poll on start
        self.poll_traffic_and_web()
        self.poll_system_metrics()
        
        # Schedule the tasks
        schedule.every(1).minutes.do(self.poll_traffic_and_web)
        schedule.every(30).minutes.do(self.poll_system_metrics)
        schedule.every().day.at(config.REPORT_TIME_IST).do(self.generate_daily_report)

        while self.running:
            schedule.run_pending()
            time.sleep(1)

if __name__ == "__main__":
    monitor = FirewallMonitor()
    
    # Testing mode: If you want to see the report immediately without waiting for 5PM
    # monitor.generate_daily_report() 

    monitor.run()
