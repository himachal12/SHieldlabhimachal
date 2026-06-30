from app.scanners.code_scanner import scan_codebase
from app.scanners.semantic_analyzer import review_all_low_confidence

findings = scan_codebase("../tests/fixtures/vulnerable_app")

low_conf = [f for f in findings if f["confidence"] < 0.7]
print(f"{len(low_conf)} findings need LLM review (this will take a bit, local 7B model)...\n")

reviewed = review_all_low_confidence(findings)

for f in reviewed:
    if "llm_reasoning" in f:
        flag = (
            "FALSE POSITIVE?"
            if f.get("is_likely_false_positive")
            else "confirmed real"
        )

        print(
            f"{f['vuln_type']:28} [{flag:16}] "
            f"conf={f['confidence']:.2f} -- {f['llm_reasoning']}"
        )