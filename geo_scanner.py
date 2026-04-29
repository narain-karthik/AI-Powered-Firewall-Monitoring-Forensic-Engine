import requests
import time

class GeoScanner:
    def __init__(self):
        self.api_url = "http://ip-api.com/json/{}"
        self.cache = {} # Cache lookups to be nice to the API

    def lookup(self, ip):
        """Fetches Location, ISP, and Server details for an IP with retries."""
        if not ip or ip in ['N/A', 'None', '']:
            return {"city": "Unknown", "country": "Unknown", "isp": "Internal", "as": "Local Network"}
            
        if ip in self.cache:
            return self.cache[ip]

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Respect rate limits for free tier ip-api (45 req/min)
                time.sleep(1.2) 
                response = requests.get(self.api_url.format(ip), timeout=15)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        result = {
                            "city": data.get('city', 'Unknown'),
                            "country": data.get('country', 'Unknown'),
                            "isp": data.get('isp', 'Unknown'),
                            "as": data.get('as', 'Unknown'),
                            "region": data.get('regionName', 'Unknown')
                        }
                        self.cache[ip] = result
                        return result
                elif response.status_code == 429:
                    print(f"[GeoScanner] Rate limited for {ip}. Waiting longer...")
                    time.sleep(5)
            except (requests.exceptions.RequestException, Exception) as e:
                print(f"[GeoScanner] Lookup attempt {attempt+1} failed for {ip}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2)
            
        return {"city": "Unknown", "country": "Unknown", "isp": "Unknown", "as": "Unknown"}

if __name__ == "__main__":
    scanner = GeoScanner()
    print("Testing GeoIP Lookup for 8.8.8.8...")
    print(scanner.lookup("8.8.8.8"))
