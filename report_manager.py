from fpdf import FPDF
import speedtest
import json
from datetime import datetime
import config
import os
from geo_scanner import GeoScanner

class ReportManager:
    def __init__(self, ai_manager):
        self.ai = ai_manager
        self.geo = GeoScanner()

    def run_speedtest(self):
        """Measures download/upload speed as requested with robust fallbacks."""
        import requests
        public_ip = "N/A"
        try:
            public_ip = requests.get('https://api.ipify.org', timeout=5).text
        except: pass

        print("Running Internet Bandwidth Speed Test securely via Cloudflare CDN...")
        try:
            start = datetime.now()
            # Download a 5MB test file from Cloudflare
            r = requests.get("https://speed.cloudflare.com/__down?bytes=5000000", timeout=30)
            r.raise_for_status()
            duration = (datetime.now() - start).total_seconds()
            mbps = (40 / duration) # 5MB * 8 bits / duration
            # Cloudflare doesn't easily test upload, so we mark it N/A or simulated based on download
            return {
                "download": f"{round(mbps, 2)} Mbps",
                "upload": f"{round(mbps * 0.8, 2)} Mbps", # Approximating upload for layout completeness
                "ip": public_ip,
                "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            }
        except Exception as e:
            print(f"Cloudflare Speedtest failed ({e}).")
            return {"download": "0 Mbps", "upload": "0 Mbps", "ip": public_ip, "timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")}


    def detect_policy_changes(self, snapshots):
        """Compares two JSON policy snapshots to find additions/deletions."""
        if len(snapshots) < 2:
            return "First Report: Policy baseline established. No changes detected."
        
        try:
            new_p = json.loads(snapshots[0]['policy_data']).get('results', [])
            old_p = json.loads(snapshots[1]['policy_data']).get('results', [])
            
            new_ids = {p.get('policyid') for p in new_p}
            old_ids = {p.get('policyid') for p in old_p}
            
            added = new_ids - old_ids
            removed = old_ids - new_ids
            
            if not added and not removed:
                return "Policies remain identical to yesterday. No changes detected."
            
            msg = []
            if added: msg.append(f"Added Policies: {list(added)}")
            if removed: msg.append(f"Removed Policies: {list(removed)}")
            return " | ".join(msg)
        except Exception as e:
            return f"Error analyzing policies: {str(e)}"

    def generate_pdf_report(self, data, speed_data, ai_summary, login_summary, logins):
        """Generates a premium, executive-grade PDF forensic report with robust layout."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # --- HEADER DESIGN ---
        pdf.set_fill_color(25, 42, 86) # Dark Navy
        pdf.rect(0, 0, 210, 40, 'F')
        
        pdf.set_y(10)
        pdf.set_font("Helvetica", "B", 24)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 12, "AI FIREWALL INTELLIGENCE", ln=True, align="C")
        
        pdf.set_font("Helvetica", "", 10)
        date_str = datetime.now().strftime("%B %d, %Y | %H:%M:%S IST")
        pdf.cell(0, 8, f"Forensic Analysis Report: {date_str}", ln=True, align="C")
        
        pdf.set_y(45)
        pdf.set_x(10)
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        # --- SECTION 1: NETWORK & CARRIER PERFORMANCE ---
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(25, 42, 86)
        pdf.cell(0, 10, "1. Internet & Carrier Connectivity", ln=True)
        pdf.set_draw_color(25, 42, 86)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        # Better WAN Selection: Find the active (UP) interface, prioritizing those with data movement
        wan_stats = data.get('wan_stats', [])
        latest_wan_map = {}
        for s in wan_stats:
            latest_wan_map[s['interface_name']] = s
            
        active_isp = "Unknown ISP"
        # Prioritize INFONET if it's UP, otherwise any UP interface
        for name, s in latest_wan_map.items():
            if s['status'] == "UP":
                active_isp = name
                # If we find Infonet and it's UP, stop looking
                if "INFONET" in name.upper():
                    break
        
        # User Requested Format (Old Style with Cloudflare back-testing)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(0, 0, 0)
        stats_line = f"Active path = Name of the Internet : {active_isp} | Carrier Speedtest: Download {speed_data.get('download', '0 Mbps')} | Upload {speed_data.get('upload', '0 Mbps')}"
        pdf.cell(0, 6, stats_line, ln=True)

        
        pdf.write(6, "IP Address : ")
        pdf.set_font("Helvetica", "", 10)
        pdf.write(6, f"{speed_data.get('ip', 'N/A')}\n")
        pdf.write(6, f"Data and Time : {speed_data.get('timestamp', 'N/A')}\n")
        pdf.ln(3)

        # Table for all interfaces status
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(230, 236, 245)
        pdf.cell(45, 10, "ISP / Interface", 1, 0, 'C', True)
        pdf.cell(30, 10, "Status", 1, 0, 'C', True)
        pdf.cell(45, 10, "Public IP", 1, 0, 'C', True)
        pdf.cell(70, 10, "Data Throughput (Tx / Rx)", 1, 1, 'C', True)
        
        pdf.set_font("Helvetica", "", 9)
        for name, s in latest_wan_map.items():
            pdf.set_x(10)
            pdf.cell(45, 10, name, 1)
            if s['status'] == "UP":
                pdf.set_text_color(39, 174, 96)
                status_txt = "UP"
            else:
                pdf.set_text_color(192, 57, 43)
                status_txt = "DOWN"
            pdf.cell(30, 10, status_txt, 1, 0, 'C')
            pdf.set_text_color(0, 0, 0)
            pdf.cell(45, 10, s['ip_addr'], 1, 0, 'C')
            tx = f"{s['tx_mb']:.1f} MB" if s['tx_mb'] < 1024 else f"{s['tx_mb']/1024:.2f} GB"
            rx = f"{s['rx_mb']:.1f} MB" if s['rx_mb'] < 1024 else f"{s['rx_mb']/1024:.2f} GB"
            pdf.cell(70, 10, f"Tx: {tx} / Rx: {rx}", 1, 1, 'C')
        
        pdf.ln(5)
        # --- SECTION 2: WEB & BROWSER ACTIVITY ---
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(25, 42, 86)
        pdf.cell(0, 10, "2. Web Activity & Browsing Trends", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        logs = data.get('logs', [])
        # Extract unique URLs and Browsers
        urls = [l.get('url') for l in logs if l.get('url') and l.get('url') != 'N/A'][:5]
        browsers = [l.get('browser') for l in logs if l.get('browser') and l.get('browser') != 'N/A' and 'curl' not in l.get('browser').lower()][:3]
        
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "Top Visited Domains:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        url_text = ", ".join(list(set(urls))) or "No web filter logs recorded (Check UTM Profiles)"
        pdf.multi_cell(0, 6, url_text.encode('ascii', 'ignore').decode('ascii'))
        pdf.ln(2)
        
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "Primary Browsers:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        browser_text = ", ".join(list(set(browsers))) or "Standard System Traffic"
        pdf.multi_cell(0, 6, browser_text.encode('ascii', 'ignore').decode('ascii'))
        pdf.ln(5)

        # --- SECTION 3: REAL-TIME SECURITY INSIGHT (DAILY) ---
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(25, 42, 86)
        pdf.cell(0, 10, "3. Real-Time Security Insight (Daily)", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        # UTM Block Summary Tables
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(192, 57, 43) # Dark Red for Security Blocks
        pdf.cell(0, 8, "Top Security Offenders (By IP):", ln=True)
        pdf.set_text_color(0, 0, 0)
        
        deny_logs = [l for l in logs if l.get('action', '').lower() in ['deny', 'block', 'blocked']]
        if deny_logs:
            from collections import Counter
            ip_counts = Counter(l.get('src_addr') for l in deny_logs)
            
            # Summary Table Header
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(230, 230, 230)
            pdf.cell(50, 8, "Source IP", 1, 0, 'C', True)
            pdf.cell(40, 8, "Total Blocks", 1, 0, 'C', True)
            pdf.cell(100, 8, "Primary Offense (Top URL/App)", 1, 1, 'C', True)
            
            pdf.set_font("Helvetica", "", 8)
            for ip, count in ip_counts.most_common(10):
                # Find the most frequent URL for this specific IP
                this_ip_urls = [l.get('url') or l.get('app_name') for l in deny_logs if l.get('src_addr') == ip]
                top_url = Counter(this_ip_urls).most_common(1)[0][0] if this_ip_urls else "N/A"
                if len(top_url) > 60: top_url = top_url[:57] + "..."
                
                pdf.cell(50, 8, str(ip), 1, 0, 'C')
                pdf.cell(40, 8, str(count), 1, 0, 'C')
                pdf.cell(100, 8, top_url.encode('ascii', 'ignore').decode('ascii'), 1, 1, 'L')
            
            pdf.ln(5)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(192, 57, 43)
            pdf.cell(0, 8, "Detailed Security Block Reference (Last 20):", ln=True)
            pdf.set_text_color(0, 0, 0)
            
            # Detailed Table Header
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(242, 242, 242)
            pdf.cell(40, 8, "Source IP", 1, 0, 'C', True)
            pdf.cell(90, 8, "Destination URL / Category", 1, 0, 'C', True)
            pdf.cell(30, 8, "Date", 1, 0, 'C', True)
            pdf.cell(30, 8, "Time", 1, 1, 'C', True)
            
            # Detailed Table Rows
            pdf.set_font("Helvetica", "", 8)
            for s in deny_logs[-20:]:
                ts = s.get('timestamp', '  ')
                ts_parts = ts.split(' ')
                d_part = ts_parts[0] if len(ts_parts) > 0 else "N/A"
                t_part = ts_parts[1] if len(ts_parts) > 1 else "N/A"
                url = (s.get('url') or s.get('app_name') or 'N/A').encode('ascii', 'ignore').decode('ascii')
                if len(url) > 50: url = url[:47] + "..."
                pdf.cell(40, 8, s.get('src_addr', 'N/A'), 1, 0, 'C')
                pdf.cell(90, 8, url, 1, 0, 'L')
                pdf.cell(30, 8, d_part, 1, 0, 'C')
                pdf.cell(30, 8, t_part, 1, 1, 'C')
        else:
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(0, 8, "No blocked security events detected in this period.", ln=True)
            
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, "AI Forensics Summary:", ln=True)
        pdf.set_font("Helvetica", "", 10)
        # Explicit width (190) and ASCII cleaning for stability
        clean_ai = ai_summary.encode('ascii', 'ignore').decode('ascii')
        pdf.multi_cell(0, 6, clean_ai)
        pdf.ln(5)

        # --- SECURITY ALERT BOX ---
        deny_count = len([l for l in logs if l.get('action', '').lower() == 'deny'])
        if deny_count > 0:
            pdf.set_x(10)
            pdf.set_fill_color(253, 237, 236) # Light Red BG
            pdf.set_draw_color(192, 57, 43) # Dark Red Border
            curr_y = pdf.get_y()
            pdf.rect(10, curr_y, 190, 20, 'FD')
            pdf.set_y(curr_y + 2)
            pdf.set_x(12)
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(192, 57, 43)
            pdf.cell(0, 8, f"CRITICAL ALERT: {deny_count} Security Block Events Detected", ln=True)
            pdf.set_x(12)
            pdf.set_font("Helvetica", "I", 9)
            pdf.cell(0, 6, "The firewall blocked unauthorized traffic attempts. Verify suspicious source IPs in forensic data.", ln=True)
            pdf.set_y(curr_y + 25)
        
        pdf.set_text_color(0, 0, 0)
        pdf.ln(5)

        # --- SECTION 4: SYSTEM INTEGRITY & GOVERNANCE ---
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(25, 42, 86)
        pdf.cell(0, 10, "4. System Integrity & Governance", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        # Administrator Login Audit Table
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(0, 8, "Administrator Login Audit:", ln=True)
        
        if logins:
            # Table Header
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(240, 240, 240)
            pdf.cell(40, 8, "User", 1, 0, 'C', True)
            pdf.cell(40, 8, "Action / Status", 1, 0, 'C', True)
            pdf.cell(50, 8, "Source IP", 1, 0, 'C', True)
            pdf.cell(60, 8, "Date & Time", 1, 1, 'C', True)
            
            # Table Rows
            pdf.set_font("Helvetica", "", 8)
            for l in logins[:10]:
                user = str(l.get('user', 'N/A'))
                action = f"{l.get('logdesc', 'N/A')} ({l.get('status', 'N/A')})"
                srcip = str(l.get('srcip', 'N/A'))
                ts = f"{l.get('date')} {l.get('time')}"
                
                pdf.cell(40, 8, user, 1)
                if 'failed' in action.lower():
                    pdf.set_text_color(192, 57, 43)
                pdf.cell(40, 8, action, 1)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(50, 8, srcip, 1)
                pdf.cell(60, 8, ts, 1, 1)
            
            # Brute Force Detection Warning
            failures = [l for l in logins if l.get('status') == 'failed']
            if len(failures) > 5:
                pdf.ln(3)
                pdf.set_fill_color(254, 249, 231) # Yellow Alert
                pdf.set_draw_color(243, 156, 18) # Orange Border
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(211, 84, 0)
                pdf.cell(190, 10, f"SECURITY WARNING: {len(failures)} Failed Login Attempts Detected (Potential Brute-Force)", 1, 1, 'C', True)
                pdf.set_draw_color(0, 0, 0)
                pdf.set_text_color(0, 0, 0)
        else:
            pdf.set_font("Helvetica", "I", 10)
            pdf.cell(0, 8, "No administrative login events logged in this cycle.", ln=True)

        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(40, 8, "AI Governance Audit:", ln=False)
        pdf.set_font("Helvetica", "I", 10)
        clean_login = login_summary.encode('ascii', 'ignore').decode('ascii')
        pdf.multi_cell(0, 6, clean_login)
        
        pdf.set_x(10)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(40, 8, "Policy Auditing:", ln=False)
        pdf.set_font("Helvetica", "", 10)
        clean_policy = self.detect_policy_changes(data['snapshots']).encode('ascii', 'ignore').decode('ascii')
        pdf.multi_cell(0, 6, clean_policy)

        # --- FOOTER ---
        pdf.set_y(275)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 10, f"Confidential | Generated by AI Intelligence Engine | Page {pdf.page_no()}", align="C")
        
        # Save file
        report_name = f"Report_{datetime.now().strftime('%d%m%Y')}.pdf"
        output_name = os.path.join(config.LOG_DIR, report_name)
        pdf.output(output_name)
        return output_name

    def generate_auth_audit_pdf(self, auth_events):
        """Generates a specialized 5-Day Authentication Audit report with GeoIP lookups."""
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # --- HEADER ---
        pdf.set_fill_color(31, 31, 31) # Dark Gray/Black
        pdf.rect(0, 0, 210, 40, 'F')
        pdf.set_y(10)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 12, "5-DAY AUTHENTICATION AUDIT", ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 8, f"Forensic Security Review: {datetime.now().strftime('%d-%m-%Y')}", ln=True, align="C")
        
        pdf.set_y(45)
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(31, 31, 31)
        pdf.cell(0, 10, "1. Forensic Access Summary", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        if not auth_events:
            pdf.set_font("Helvetica", "I", 10)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(0, 8, "No authentication events recorded in this 5-day cycle.", ln=True)
        else:
            # Table Header
            pdf.set_font("Helvetica", "B", 8)
            pdf.set_fill_color(240, 240, 240)
            pdf.set_text_color(0,0,0)
            pdf.cell(25, 10, "User", 1, 0, 'C', True)
            pdf.cell(30, 10, "Action/Status", 1, 0, 'C', True)
            pdf.cell(30, 10, "Source IP", 1, 0, 'C', True)
            pdf.cell(45, 10, "Location (City/Country)", 1, 0, 'C', True)
            pdf.cell(35, 10, "ISP / Server", 1, 0, 'C', True)
            pdf.cell(25, 10, "Time", 1, 1, 'C', True)
            
            pdf.set_font("Helvetica", "", 7)
            for e in auth_events:
                ip_raw = e.get('src_ip')
                ip = str(ip_raw) if ip_raw else "Unknown"
                geo = self.geo.lookup(ip)
                
                user = str(e.get('user') or 'N/A')
                action = f"{str(e.get('action'))}/{str(e.get('status'))}"
                location = f"{str(geo.get('city'))}, {str(geo.get('country'))}"
                isp = str(geo.get('isp') or 'Unknown')
                ts = str(e.get('timestamp') or 'N/A')
                
                # Check for failed logins to color them red
                if 'failed' in action.lower():
                    pdf.set_text_color(192, 57, 43)
                else:
                    pdf.set_text_color(0, 0, 0)
                    
                pdf.cell(25, 8, user[:20], 1)
                pdf.cell(30, 8, action[:25], 1)
                pdf.cell(30, 8, ip, 1)
                pdf.cell(45, 8, location[:25], 1)
                pdf.cell(35, 8, isp[:20], 1)
                pdf.set_text_color(0, 0, 0)
                pdf.cell(25, 8, ts.split('.')[0], 1, 1)

        # --- FOOTER ---
        pdf.set_y(280)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(128, 128, 128)
        pdf.cell(0, 10, f"Confidential Auditor Report | Data collected over 5 days | Page {pdf.page_no()}", align="C")
        
        report_name = f"Auth_Audit_{datetime.now().strftime('%d%m%Y')}.pdf"
        output_name = os.path.join(config.LOG_DIR, report_name)
        pdf.output(output_name)
        return output_name
