import requests
import json
import config
import time

class AIManager:
    def __init__(self):
        self.url = config.OLLAMA_URL
        self.model = config.OLLAMA_MODEL

    def _aggregate_blocks(self, logs):
        """Pre-processes logs into a tiny statistical summary for the AI."""
        from collections import Counter
        denies = [l for l in logs if l.get('action', '').lower() in ['deny', 'block', 'blocked']]
        
        if not denies:
            return "No security blocks detected today."
            
        ip_counts = Counter(l.get('src_addr') for l in denies)
        
        summary = "TOP BLOCKED IP SOURCES:\n"
        for ip, count in ip_counts.most_common(10):
            # Find common URLs for this IP
            ip_urls = list(set([l.get('url') or l.get('app_name') for l in denies if l.get('src_addr') == ip]))
            url_list = ", ".join(ip_urls[:3])
            summary += f"- IP: {ip} | Block Count: {count} | Examples: {url_list}\n"
        return summary

    def _safe_ollama_request(self, payload, max_retries=3):
        """Helper to handle Ollama requests with retries for runner crashes."""
        headers = {}
        if getattr(config, 'OLLAMA_API_KEY', None):
            headers["Authorization"] = f"Bearer {config.OLLAMA_API_KEY}"
            
        for attempt in range(max_retries):
            try:
                response = requests.post(self.url, json=payload, headers=headers, timeout=180)
                response.raise_for_status()
                res_json = response.json()
                
                if "error" in res_json:
                    # Specific check for runner termination
                    if "terminated" in res_json["error"].lower() or "nil" in res_json["error"].lower():
                        print(f"[AI Manager] Warning: Ollama runner crashed (Attempt {attempt+1}/{max_retries}). Waiting for restart...")
                        time.sleep(3)
                        continue
                    print(f"[AI Manager ERROR] Ollama Error: {res_json['error']}")
                    return None
                    
                return res_json.get('response')
            except (requests.exceptions.RequestException, Exception) as e:
                print(f"[AI Manager] Connection attempt {attempt+1} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
                else:
                    break
        return None

    def analyze_traffic(self, logs):
        """Generates a forensic summary. Now uses pre-aggregated stats for stability."""
        if not logs:
            return "No traffic logs were recorded for this period."

        # Aggregate denys into a small text summary to save memory
        security_summary = self._aggregate_blocks(logs)
        
        prompt = f"""
        You are an expert Cybersecurity Analyst. Analyze these aggregated firewall statistics and provide a professional forensic executive summary.
        
        STATISTICAL SUMMARY:
        {security_summary}
        
        GOAL: Summarize the risk posture. Identify which internal IPs are most active in violating policy and what they are trying to access.
        
        Provide a clear, concise forensic analysis. Avoid long introductory text.
        """

        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {"num_ctx": 4096} # Increased context for forensic analysis
            }
            
            print(f"\n[AI Manager] Sending Summary to Ollama ({self.model})...")
            result = self._safe_ollama_request(payload)
            
            if not result:
                return "AI Summary is currently unavailable (Ollama service issue). Please check if Ollama is running."
                
            return result
        except Exception as e:
            print(f"\n[AI Manager ERROR] Traffic analysis failed: {e}")
            return "AI Summary failed to generate due to a system error."

    def summarize_login_activity(self, events):
        """Analyzes login events to identify security trends or failed attempts."""
        if not events:
            return "No administrative login events were found today."

        prompt = f"""
        Summarize the following administrative login events for a security report. 
        Identify if there are any failed attempts or unusual login times.
        
        EVENTS:
        {json.dumps(events, indent=2)}
        """

        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "num_ctx": 4096
                }
            }
                
            print(f"\n[AI Manager] Sending Login Logs to Ollama ({self.model})...")
            start_time = time.time()
            
            result = self._safe_ollama_request(payload)
            
            elapsed = time.time() - start_time
            if result:
                print(f"[AI Manager] Successfully received Login Analysis in {elapsed:.2f} seconds.")
                return result
            else:
                return "AI failed to analyze login activity (Ollama Timeout)."
        except Exception as e:
            print(f"\n[AI Manager ERROR] Login analysis failed: {e}")
            return "AI failed to analyze login activity."
