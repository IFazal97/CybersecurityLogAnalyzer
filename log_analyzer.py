import re

# Define the log file path
LOG_FILE = "sample_log.txt"

# Define suspicious HTTP status codes to detect
SUSPICIOUS_CODES = ['401', '403']

def parse_log_line(line):
    """
    Parse a single log line and extract IP and status code.
    Returns tuple (ip, status_code) or None if no match.
    """
    pattern = r'(\d+\.\d+\.\d+\.\d+).+\".+\" (\d{3}) '
    match = re.search(pattern, line)
    if match:
        ip = match.group(1)
        status_code = match.group(2)
        return ip, status_code
    return None

def analyze_logs(log_file):
    """
    Analyze the log file for suspicious activity.
    Returns dictionary {ip: count_of_suspicious_events}
    """
    suspicious_activity = {}
    with open(log_file, 'r') as file:
        for line in file:
            result = parse_log_line(line)
            if result:
                ip, code = result
                if code in SUSPICIOUS_CODES:
                    suspicious_activity[ip] = suspicious_activity.get(ip, 0) + 1
    return suspicious_activity

def generate_report(activity):
    """
    Print summary report of suspicious activity.
    """
    if not activity:
        print("No suspicious activity found.")
        return
    print("Suspicious activity detected:")
    for ip, count in activity.items():
        print(f"IP Address {ip} had {count} suspicious event(s)")

if __name__ == "__main__":
    suspicious_activity = analyze_logs(LOG_FILE)
    generate_report(suspicious_activity)
