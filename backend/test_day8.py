"""
Day 8 end-to-end test
Tests the complete pipeline through the actual API
"""

import time
import requests

BASE_URL = "http://localhost:8000"


def poll_until_complete(scan_id: str, max_wait: int = 600) -> dict:
    """Poll /api/status until scan is done or failed."""
    print(f"\nPolling scan {scan_id}...")
    start = time.time()

    while time.time() - start < max_wait:
        r = requests.get(f"{BASE_URL}/api/status/{scan_id}")
        data = r.json()
        status = data.get("status")
        progress = data.get("progress", 0)
        stage = data.get("current_stage", "")

        print(f"  [{progress:3}%] {status} — {stage}")

        if status == "completed":
            return data
        elif status == "failed":
            print(f"  FAILED: {data.get('error')}")
            return data

        time.sleep(5)

    print("  Timed out waiting for scan")
    return {}


print("=" * 70)
print("TEST 1: Code scan via API")
print("=" * 70)

# Use a small, known-vulnerable public repo
r = requests.post(f"{BASE_URL}/api/scan/code", json={
    "repo_url": "https://github.com/OWASP/WebGoat",
    "scan_type": "code"
})
print(f"Response: {r.json()}")
scan_id = r.json().get("scan_id")

if scan_id:
    final = poll_until_complete(scan_id, max_wait=300)
    print(f"\nFinal status: {final.get('status')}")
    print(f"Findings: {final.get('total_findings')} total")
    print(f"  Critical: {final.get('critical_count')}")
    print(f"  High:     {final.get('high_count')}")

    if final.get("status") == "completed":
        r2 = requests.get(f"{BASE_URL}/api/results/{scan_id}")
        if r2.status_code == 200:
            results = r2.json()
            print(f"\nTop 3 findings:")
            for f in results.get("findings", [])[:3]:
                print(f"  [{f['severity']}] {f['vuln_type']} — CVSS {f.get('cvss_score')}")
                if f.get("fix_explanation"):
                    print(f"    Fix: {f['fix_explanation'][:80]}...")

print("\n" + "=" * 70)
print("TEST 2: Web scan via API")
print("=" * 70)

r = requests.post(f"{BASE_URL}/api/scan/web", json={
    "domain": "scanme.nmap.org",
    "scan_mode": "passive"
})
print(f"Response: {r.json()}")
scan_id2 = r.json().get("scan_id")

if scan_id2:
    final2 = poll_until_complete(scan_id2, max_wait=300)
    print(f"\nFinal: {final2.get('total_findings')} findings")