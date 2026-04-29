# Configuration for AI Powered Firewall Monitoring

# --- FortiGate 100F API Settings ---
FGT_IP = "192.160.207.176:4449"
FGT_API_KEY = "rhrfbfG5NQ9pQmzfb55yt98wgHfQxh"

# --- AI Settings (Local Ollama / Cloud API) ---
OLLAMA_MODEL = "phi3:latest"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_API_KEY = "4c35061a53ea4586a6c1cdc5c680cc80.wv7x4W5BOD4kzO_OYvyPBRlW"

# --- SMTP / Email Settings ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
# The User's provided SMTP Account Details
SMTP_USER = "narainjkans@gmail.com" 
SMTP_PASS = "lugnxurevlqacssw" # App Password
RECIPIENT_MAIL = "narainjkans1@gmail.com"

# --- System Settings ---
POLL_INTERVAL_MINS = 30
REPORT_TIME_IST = "17:00" # 5:00 PM
DB_PATH = "firewall_data.db"
LOG_DIR = "daily_logs"
