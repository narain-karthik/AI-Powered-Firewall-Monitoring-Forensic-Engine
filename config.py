# Configuration for AI Powered Firewall Monitoring

# --- FortiGate 100F API Settings ---
FGT_IP = ""
FGT_API_KEY = ""

# --- AI Settings (Local Ollama / Cloud API) ---
OLLAMA_MODEL = "phi3:latest"
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_API_KEY = ""

# --- SMTP / Email Settings ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
# The User's provided SMTP Account Details
SMTP_USER = "" 
SMTP_PASS = "" # App Password
RECIPIENT_MAIL = ""

# --- System Settings ---
POLL_INTERVAL_MINS = 30
REPORT_TIME_IST = "17:00" # 5:00 PM
DB_PATH = "firewall_data.db"
LOG_DIR = "daily_logs"
