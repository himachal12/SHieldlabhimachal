from app.scanners.web_scanner import scan_web_target

findings = scan_web_target("scanme.nmap.org")

print(f"Total findings: {len(findings)}\n")

for f in findings:
    print(
        f"[{f['severity']:8}] "
        f"{f['vuln_type']:28} "
        f"(source={f['source']}) -- {f['description']}"
    )