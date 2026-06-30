from app.scanners.web_scanner import scan_web_target

findings = scan_web_target("127.0.0.1")

print(f"Findings: {len(findings)}")

for f in findings:
    print(f"  {f['vuln_type']}: {f['description']}")