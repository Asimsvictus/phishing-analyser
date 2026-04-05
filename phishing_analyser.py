import email
import re
import requests
import json
from datetime import datetime

# VirusTotal API key
VT_API_KEY = "fdf78e6511754270a165fb24a1286e35dd46d2c5ff4c5eea1eb4bee8448181f7"
VT_URL_SCAN = "https://www.virustotal.com/api/v3/urls"
VT_URL_REPORT = "https://www.virustotal.com/api/v3/urls/{}"

def extract_headers(msg):
    print("\n[*] Analysing email headers...")
    findings = []

    sender = msg.get("From", "Not found")
    reply_to = msg.get("Reply-To", "Not found")
    received = msg.get("Received", "Not found")
    spf = msg.get("Received-SPF", "Not found")
    dkim = msg.get("DKIM-Signature", "Not found")

    print(f"    From:       {sender}")
    print(f"    Reply-To:   {reply_to}")
    print(f"    SPF:        {spf}")
    print(f"    DKIM:       {'Present' if dkim != 'Not found' else 'Missing'}")

    # Check for spoofing indicators
    if reply_to != "Not found" and reply_to != sender:
        findings.append(f"SUSPICIOUS: Reply-To ({reply_to}) differs from From ({sender})")

    if spf == "Not found":
        findings.append("WARNING: No SPF record found — sender may be spoofed")

    if dkim == "Not found":
        findings.append("WARNING: No DKIM signature — email integrity unverified")

    return findings

def extract_urls(msg):
    print("\n[*] Extracting URLs from email body...")
    urls = []
    url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
            elif part.get_content_type() == "text/html":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    urls = list(set(url_pattern.findall(body)))
    print(f"    Found {len(urls)} unique URLs")
    for url in urls:
        print(f"    - {url}")
    return urls

def check_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}

    # Submit URL for scanning
    response = requests.post(
        VT_URL_SCAN,
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return {"url": url, "result": "API error", "malicious": 0, "total": 0}

    scan_id = response.json()["data"]["id"]

    # Get the report
    report_response = requests.get(
        VT_URL_REPORT.format(scan_id),
        headers=headers
    )

    if report_response.status_code != 200:
        return {"url": url, "result": "Report error", "malicious": 0, "total": 0}

    stats = report_response.json()["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    total = sum(stats.values())

    return {
        "url": url,
        "malicious": malicious,
        "total": total,
        "result": "MALICIOUS" if malicious > 0 else "CLEAN"
    }

def analyse_urls(urls):
    print("\n[*] Checking URLs against VirusTotal...")
    results = []
    for url in urls:
        print(f"    Checking: {url}")
        result = check_url_virustotal(url)
        results.append(result)
        status = f"[!] MALICIOUS ({result['malicious']}/{result['total']} engines)" if result['malicious'] > 0 else f"[+] CLEAN (0/{result['total']} engines)"
        print(f"    Result:   {status}")
    return results

def generate_report(header_findings, url_results, email_file):
    print("\n" + "="*60)
    print("PHISHING ANALYSIS REPORT")
    print("="*60)
    print(f"File analysed:  {email_file}")
    print(f"Time:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    print("\n--- HEADER ANALYSIS ---")
    if header_findings:
        for f in header_findings:
            print(f"  [!] {f}")
    else:
        print("  [+] No header anomalies detected")

    print("\n--- URL ANALYSIS ---")
    malicious_urls = [r for r in url_results if r['malicious'] > 0]
    clean_urls = [r for r in url_results if r['malicious'] == 0]

    for r in url_results:
        flag = "[!] MALICIOUS" if r['malicious'] > 0 else "[+] CLEAN"
        print(f"  {flag} — {r['url']}")
        print(f"           Detections: {r['malicious']}/{r['total']} engines")

    print("\n--- VERDICT ---")
    if malicious_urls or header_findings:
        print("  [!] SUSPICIOUS — This email shows indicators of phishing")
        if malicious_urls:
            print(f"      {len(malicious_urls)} malicious URL(s) detected")
        if header_findings:
            print(f"      {len(header_findings)} header anomaly(s) detected")
    else:
        print("  [+] CLEAN — No phishing indicators detected")

    print("="*60)

    # Save report to file
    report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_name, "w") as f:
        f.write("PHISHING ANALYSIS REPORT\n")
        f.write(f"File: {email_file}\n")
        f.write(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("HEADER FINDINGS:\n")
        for finding in header_findings:
            f.write(f"  {finding}\n")
        f.write("\nURL RESULTS:\n")
        for r in url_results:
            f.write(f"  {r['result']} — {r['url']} ({r['malicious']}/{r['total']} engines)\n")

    print(f"\n[*] Report saved to {report_name}")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 phishing_analyser.py <email_file.eml>")
        return

    email_file = sys.argv[1]

    try:
        with open(email_file, "r") as f:
            msg = email.message_from_file(f)
    except FileNotFoundError:
        print(f"[!] File not found: {email_file}")
        return

    print(f"\n[*] Phishing Analysis Toolkit")
    print(f"[*] Analysing: {email_file}")

    header_findings = extract_headers(msg)
    urls = extract_urls(msg)
    url_results = analyse_urls(urls) if urls else []
    generate_report(header_findings, url_results, email_file)

if __name__ == "__main__":
    main()
