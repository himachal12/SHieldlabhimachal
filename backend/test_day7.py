"""
Day 7 integration test
Passive mode only against scanme.nmap.org (safe, legal target)
"""

from app.scanners.web_scanner import scan_web_target
from app.agents.severity_reasoning import reason_all_severities
from app.config import ScanMode

TARGET = "scanme.nmap.org"

print("=" * 70)
print(f"STEP 1: Passive web scan of {TARGET}")
print("=" * 70)

findings = scan_web_target(
    target=TARGET,
    scan_mode=ScanMode.PASSIVE  # default, no consent needed
)

print(f"\nPassive scan findings: {len(findings)}")
for f in findings:
    mode_tag = f.get("scan_mode", "passive")
    print(f"  [{f['severity']:8}] {f['vuln_type']:30} (source={f['source']}, mode={mode_tag})")

print()
print("=" * 70)
print("STEP 2: Severity Reasoning (Groq CVSS scoring)")
print("=" * 70)

findings = reason_all_severities(findings)

print("\nScored findings (sorted by CVSS):")
for f in sorted(findings, key=lambda x: x.get("cvss_score", 0), reverse=True):
    cvss = f.get("cvss_score", "N/A")
    reasoning = f.get("severity_reasoning", "")[:75]
    print(f"  CVSS {str(cvss):4} [{f['severity']:8}] {f['vuln_type']}")
    if reasoning:
        print(f"           → {reasoning}")

print()
print("=" * 70)
print("ACTIVE MODE DEMONSTRATION (showing consent gate works)")
print("=" * 70)

# Test that active mode WITHOUT consent safely falls back to passive
print("\nTest 1: Active mode, consent NOT confirmed (should fall back to passive):")
findings_no_consent = scan_web_target(
    target=TARGET,
    scan_mode=ScanMode.ACTIVE,
    consent_confirmed=False  # No consent -- should refuse active scan
)
active_findings = [f for f in findings_no_consent if f.get("scan_mode") == "active"]
print(f"  Active findings: {len(active_findings)} (expected: 0 -- consent gate worked)")

# Test that active mode WITH consent but no URLs tells user what's needed
print("\nTest 2: Active mode, consent confirmed, no active_urls (should warn and skip sqlmap):")
findings_no_urls = scan_web_target(
    target=TARGET,
    scan_mode=ScanMode.ACTIVE,
    consent_confirmed=True,
    active_urls=[]  # No URLs to test -- sqlmap needs targets
)
active_findings2 = [f for f in findings_no_urls if f.get("scan_mode") == "active"]
print(f"  Active findings: {len(active_findings2)} (expected: 0 -- no URLs to test)")

print("\n✅ Day 7 complete!")
print("\nFor a real active scan (on YOUR OWN target), the call would be:")
print("""
  scan_web_target(
      target="YOUR-OWN-DOMAIN.com",
      scan_mode=ScanMode.ACTIVE,
      consent_confirmed=True,
      active_urls=["http://YOUR-OWN-DOMAIN.com/search?q=test"]
  )
""")