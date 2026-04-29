from db_manager import DBManager
from report_manager import ReportManager
from ai_manager import AIManager
from mail_manager import MailManager
import config

def test_audit_report():
    print("--- 5-DAY AUTHENTICATION AUDIT TEST ---")
    
    db = DBManager()
    ai = AIManager()
    report = ReportManager(ai)
    mail = MailManager()
    
    print("Fetching auth logs from database...")
    auth_events = db.get_auth_logs(days=5)
    
    if not auth_events:
        print("[!] No auth events found in DB. Run main.py first to collect data.")
        return

    print(f"Generating Forensic PDF with GeoIP lookups for {len(auth_events)} events...")
    # This will use GeoScanner to look up every unique IP
    pdf_path = report.generate_auth_audit_pdf(auth_events)
    
    print(f"[SUCCESS] Audit Report generated: {pdf_path}")
    print(f"Sending to {config.RECIPIENT_MAIL}...")
    
    mail.send_report(pdf_path, config.RECIPIENT_MAIL)
    print("Check your email for the '5-DAY AUTHENTICATION AUDIT' report.")

if __name__ == "__main__":
    test_audit_report()
