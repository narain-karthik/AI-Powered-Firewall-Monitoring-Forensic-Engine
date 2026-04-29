from main import FirewallMonitor
import config

print("--- AI MONITOR TESTING MODE ---")
print("Initializing Firewall Monitor for a single report run...")

monitor = FirewallMonitor()

# Manually trigger the daily report process
print("\nStarting Test Report Generation...")
print("This will run a Speed Test, fetch AI Analysis, create a PDF, and send an Email.")

try:
    monitor.generate_daily_report()
    print("\n[SUCCESS] Test report sent! Please check your email (narainjkans1@gmail.com).")
except Exception as e:
    print(f"\n[ERROR] Test report failed: {e}")
