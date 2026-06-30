"""
Day 5 validation script -- runs the complete pipeline:
scan -> semantic filter -> fix generation
"""

from app.scanners.code_scanner import scan_codebase
from app.scanners.semantic_analyzer import review_all_low_confidence
from app.agents.fix_generation import generate_all_fixes

print("=" * 70)
print("STEP 1: Scanning codebase...")
findings = scan_codebase("../tests/fixtures/vulnerable_app")
print(f"Found {len(findings)} raw findings\n")

print("=" * 70)
print("STEP 2: Running semantic false-positive filter...")
findings = review_all_low_confidence(findings)
print("Done\n")

print("=" * 70)
print("STEP 3: Generating fixes...")
findings = generate_all_fixes(findings)
print("Done\n")

print("=" * 70)
print("FULL RESULTS:")
print("=" * 70)

for f in findings:
    print(f"\n[{f['severity']}] {f['vuln_type']} (line {f.get('line_number')}, source={f['source']})")
    print(f"  Confidence: {f['confidence']:.2f}")
    if f.get("is_likely_false_positive"):
        print(f"  ⚠️  LLM flagged as possible false positive")
    print(f"  Original: {f.get('vulnerable_code') or '(no code snippet)'}")
    print(f"  Fix source: {f['fix_source']}")
    if f.get("fixed_code"):
        print(f"  FIXED CODE:\n    {f['fixed_code']}")
    print(f"  Explanation: {f['fix_explanation']}")
    print(f"  Remediation time: {f['remediation_time']}")