import json
import os
import glob
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = ROOT / "data" / "raw" / "semgrep-rules"
OUT_PATH = ROOT / "data" / "processed" / "semgrep_security.jsonl"

def extract_examples_from_rule(rule, source_file):
    rule_id = rule.get("id", "unknown-id")
    message = rule.get("message", "")
    languages = rule.get("languages", [])
    severity = rule.get("severity", "")
    md = rule.get("metadata", {}) or {}
    cwe = md.get("cwe") or md.get("cwe_id") or "Unknown"
    owasp = md.get("owasp", "Unknown")
    refs = md.get("references", [])

    examples = []

    def make_example(pattern_desc: str):
        return {
            "instruction": "You are a secure code reviewer. Identify and explain any security vulnerabilities in the given code pattern.",
            "input": f"Language(s): {', '.join(languages) or 'unknown'}\n"
                     f"Semgrep rule id: {rule_id}\n"
                     f"Pattern:\n{pattern_desc}",
            "output": (
                f"Vulnerability rule: {rule_id}\n"
                f"Message: {message}\n"
                f"Severity: {severity or 'UNSPECIFIED'}\n"
                f"CWE: {cwe}\n"
                f"OWASP: {owasp}\n"
                f"Explanation: This pattern is associated with a potential security issue. "
                f"Describe how the vulnerability may occur and how to fix it.\n"
                f"Source rule file: {source_file}"
            )
        }

    # --- Handle single key "pattern" -----------------------
    if "pattern" in rule and rule["pattern"]:
        examples.append(make_example(rule["pattern"]))

    # --- Handle list under "patterns" -----------------------
    patterns_list = rule.get("patterns") or []   # <-- FIXED HERE
    for p in patterns_list:
        if isinstance(p, dict) and "pattern" in p and p["pattern"]:
            examples.append(make_example(p["pattern"]))

    # --- Handle "pattern-either" ---------------------------
    pattern_either = rule.get("pattern-either") or []
    for p in pattern_either:
        if isinstance(p, dict) and "pattern" in p:
            examples.append(make_example(p["pattern"]))
        elif isinstance(p, str):
            examples.append(make_example(p))

    # --- Optional: pattern-regex (some rules use this)
    if "pattern-regex" in rule and rule["pattern-regex"]:
        examples.append(make_example(rule["pattern-regex"]))

    return examples


def main():
    os.makedirs(OUT_PATH.parent, exist_ok=True)
    count = 0

    with OUT_PATH.open("w", encoding="utf-8") as out_f:
        for yaml_path in glob.glob(str(RULES_DIR / "**" / "*.yaml"), recursive=True):
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
            except Exception:
                continue

            if not isinstance(data, dict) or "rules" not in data:
                continue

            for rule in data.get("rules", []):
                try:
                    examples = extract_examples_from_rule(rule, source_file=os.path.relpath(yaml_path, RULES_DIR))
                except Exception:
                    continue

                for ex in examples:
                    out_f.write(json.dumps(ex, ensure_ascii=False) + "\n")
                    count += 1

    print(f"Wrote {count} examples to {OUT_PATH}")


if __name__ == "__main__":
    main()
