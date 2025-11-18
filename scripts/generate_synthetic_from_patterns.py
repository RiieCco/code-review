import json
import ast
import random
from pathlib import Path

SRC = Path("data/processed/semgrep_security.jsonl")
OUT = Path("data/processed/semgrep_synthetic.jsonl")

def create_synthetic_example(lang, rule_id, pattern, message, cwe):
    # Basic placeholder snippet generator.
    # Later we can upgrade to a full AST or templating engine.
    
    if lang == "python":
        if "$X == $X" in pattern:
            vulnerable = """
def check_value(x):
    if x == x:
        print("Always true")
"""
            fixed = """
def check_value(x):
    print("Value received:", x)
"""
        elif "$X.unsafe_get" in pattern:
            vulnerable = """
def read_value(arr, idx):
    return arr.unsafe_get(idx)
"""
            fixed = """
def read_value(arr, idx):
    return arr[idx]    # bounds-checked access
"""
        else:
            # generic fallback for unknown patterns
            vulnerable = f"# Code matching pattern: {pattern}\npass"
            fixed = "# safer alternative implementation\npass"
    else:
        vulnerable = f"// Code for {lang} matching pattern {pattern}"
        fixed = f"// Safe alternative for {lang}"

    return {
        "instruction": "You are a secure code reviewer. Identify vulnerabilities and propose a fix.",
        "input": f"Language: {lang}\nRule: {rule_id}\nCode:\n{vulnerable}",
        "output": (
            f"Rule: {rule_id}\n"
            f"Pattern: {pattern}\n"
            f"Message: {message}\n"
            f"CWE: {cwe}\n"
            f"Detected Vulnerability Explanation: explain why this code is unsafe.\n"
            f"Here is a corrected version:\n{fixed}"
        )
    }

def main():
    out_f = OUT.open("w", encoding="utf-8")
    with SRC.open() as src_f:
        for line in src_f:
            row = json.loads(line)
            inp = row["input"]
            out = row["output"]

            # Extract fields
            try:
                lang = inp.split("Language(s): ")[1].split("\n")[0]
                rule_id = inp.split("Semgrep rule id: ")[1].split("\n")[0]
                pattern = inp.split("Pattern:\n")[1]
                message = out.split("Message: ")[1].split("\n")[0]
                cwe = out.split("CWE: ")[1].split("\n")[0]
            except Exception:
                continue

            synthetic = create_synthetic_example(lang, rule_id, pattern, message, cwe)
            out_f.write(json.dumps(synthetic, ensure_ascii=False) + "\n")

    out_f.close()
    print("Saved synthetic examples to", OUT)

if __name__ == "__main__":
    main()
