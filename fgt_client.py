import requests
import urllib3
import json
import os
import hashlib
from datetime import datetime
import config

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class FortiGateClient:
    def __init__(self):
        self.ip = config.FGT_IP
        self.api_key = config.FGT_API_KEY
        self.base_url = f"https://{self.ip}/api/v2"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        self.app_dict = {}
        try:
            dict_path = os.path.join(os.path.dirname(__file__), "app_dictionary.json")
            if os.path.exists(dict_path):
                with open(dict_path, 'r') as f:
                    self.app_dict = json.load(f)
        except Exception as e:
            print(f"Failed to load app dictionary: {e}")

    def _get(self, endpoint, params=None):
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params, verify=False, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            # Silently handle errors to avoid crashing the scheduler, but log if needed
            print(f"API Error at {endpoint}: {e}")
            return None

    def get_system_status(self):
        """Fetch Hardware CPU, RAM, and Session usage."""
        return self._get("monitor/system/resource/usage")

    def get_active_sessions(self, count=50):
        """Fetch real-time traffic sessions."""
        params = {"count": count}
        return self._get("monitor/firewall/session", params=params)

    def get_traffic_logs(self, count=50, family='ipv4'):
        """Fetch real-time traffic sessions to ensure JSON is always populated.
           Family can be 'ipv4' or 'ipv6'.
        """
        params = {"count": count}
        if family == 'ipv6':
            params['ip_version'] = 'ipv6' # Correct parameter for v7.2.10 session API
            
        res = self._get("monitor/firewall/session", params=params)
        if res and 'results' in res:
            # Session API returns results as a dict with a 'details' list
            if isinstance(res['results'], dict):
                return res['results'].get('details', [])
            # Some versions return as a direct list
            return res['results']
        return []

    def get_memory_logs(self, category, count=50):
        """Fetch logs from a specific memory category (webfilter, app-ctrl, ips, etc.)"""
        params = {"count": count}
        res = self._get(f"log/memory/{category}", params=params)
        if res and 'results' in res:
            return res['results']
        return []

    def get_web_logs(self, count=50):
        """Legacy helper - redirects to get_memory_logs('webfilter')"""
        return self.get_memory_logs("webfilter", count)

    def get_denied_traffic(self, count=20):
        """Fetch only denied/blocked traffic logs."""
        params = {"count": count, "log-type": "traffic", "filter": "action==deny"}
        res = self._get("log/forward", params=params)
        if res and 'results' in res:
            return res['results']
        return []

    def get_event_logs(self, count=50):
        """Fetch administrator and system login events."""
        params = {"count": count}
        # Confirmed path for v7.2.10 system logins
        return self._get("log/memory/event/user", params=params)

    def get_vpn_status(self):
        """Fetch active VPN users and tunnels."""
        tunnels = self._get("monitor/vpn/ssl/tunnels")
        stats = self._get("monitor/vpn/ssl/stats")
        return {
            "tunnels": tunnels.get('results', []) if tunnels else [],
            "stats": stats.get('results', []) if stats else {}
        }

    def get_policy_snapshot(self):
        """Fetch all firewall policies to detect changes."""
        return self._get("cmdb/firewall/policy")

    def get_interface_stats(self):
        """Fetch bandwidth stats for speed report."""
        return self._get("monitor/system/interface")

    def get_wan_stats(self):
        """Specifically extracts stats for INFONET_ISP (port7) and BSNL-WAN2 (port3)."""
        res = self._get("monitor/system/interface")
        if not res or 'results' not in res: return {}
        
        interfaces = res['results']
        wan_data = {}
        for port in ['port7', 'port3']:
            if port in interfaces:
                p = interfaces[port]
                wan_data[port] = {
                    "name": p.get('alias', port),
                    "ip": p.get('ip', '0.0.0.0'),
                    "status": "UP" if p.get('link') else "DOWN",
                    "tx": round(p.get('tx_bytes', 0) / (1024*1024), 2), # MB total
                    "rx": round(p.get('rx_bytes', 0) / (1024*1024), 2), # MB total
                }
        return wan_data

    def format_forensic_data(self, s):
        """Standardizes raw log data (Traffic and Web) for the database and JSON."""
        # Detect if it's a UTM Memory log or a Session Monitor object
        is_utm = 'subtype' in s or 'logid' in s
        
        # Source/Dest Addr Mapping (UTM uses 'srcip', Session uses 'saddr')
        src_addr = s.get('srcip') or s.get('saddr') or s.get('src-ip') or 'N/A'
        dst_addr = s.get('dstip') or s.get('daddr') or s.get('dst-ip') or 'N/A'
        src_port = s.get('srcport') or s.get('sport') or 0
        dst_port = s.get('dstport') or s.get('dport') or 0
        
        # Application Name Extraction
        app_name = 'N/A'
        apps = s.get('apps', [])
        app_names = []
        
        if is_utm:
            # Use App-Ctrl categories if available
            app_name = s.get('app') or s.get('appcat') or 'N/A'
            if s.get('subtype') == 'webfilter':
                app_name = "Web Browsing"
        elif isinstance(apps, list) and apps:
            for a in apps:
                if a.get('name'):
                    app_names.append(a.get('name'))
                elif 'id' in a:
                    app_id_str = str(a.get('id'))
                    if app_id_str in self.app_dict and app_id_str != "0":
                        app_names.append(self.app_dict[app_id_str])
            app_name = ", ".join(app_names) if app_names else 'N/A'
        
        # Log ID / Session ID handling
        log_id = str(s.get('logid') or s.get('sessionid') or s.get('id') or 'N/A')
        
        # Calculate a reliable timestamp
        ts = s.get('timestamp')
        if not ts:
            date_str = s.get('date', '').strip()
            time_str = s.get('time', '').strip()
            if date_str and time_str:
                ts = f"{date_str} {time_str}"
            else:
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if log_id == 'N/A':
            # Generate a unique hash for active sessions based on socket and captured time
            raw = f"{src_addr}-{dst_addr}-{src_port}-{dst_port}-{ts}"
            log_id = "sess_" + hashlib.md5(raw.encode()).hexdigest()[:8]
            
        # User-Agent/Browser extraction
        user_agent = s.get('useragent') or s.get('browser') or 'N/A'
        
        return {
            'log_id': log_id,
            'timestamp': ts,
            'type': s.get('type') or 'traffic',
            'action': s.get('action') or 'Accept',
            'src_addr': src_addr,
            'src_port': src_port,
            'dst_addr': dst_addr,
            'dst_port': dst_port,
            'policy_id': str(s.get('policyid') or s.get('policy-id') or '0'),
            'service_name': s.get('service') or s.get('proto') or 'N/A',
            'app_name': app_name,
            'sent_bytes': int(s.get('sentbyte') or s.get('sent-bytes') or s.get('sent_bytes') or 0),
            'rcvd_bytes': int(s.get('rcvdbyte') or s.get('recv-bytes') or s.get('rcvd_bytes') or 0),
            'location': s.get('country') or s.get('srccountry') or 'Internal',
            'msg': s.get('msg') or 'N/A',
            'url': s.get('url') or s.get('hostname') or 'N/A',
            'browser': user_agent
        }
