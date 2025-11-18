#!/usr/bin/env python3
"""
Convert enriched ASVS knowledge objects into multi-example Alpaca-style
instruction training samples for DeepSeek (or any instruction-tuned LLM).

Input:  data/processed/asvs.enriched.jsonl
Output: data/processed/asvs.alpaca.jsonl
"""

import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
ENRICHED_PATH = ROOT / "data" / "processed" / "asvs.enriched.jsonl"
OUT_PATH = ROOT / "data" / "processed" / "asvs.alpaca.jsonl"


def _extract_snippets(field: Any) -> List[str]:
    """
    Normalize insecure_examples / secure_examples which might be:
      - list of strings
      - list of dicts with 'code' or 'snippet'
      - single string
    Return a list of code strings.
    """
    snippets: List[str] = []

    if field is None:
        return snippets

    if isinstance(field, str):
        return [field]

    if isinstance(field, list):
        for item in field:
            if isinstance(item, str):
                snippets.append(item)
            elif isinstance(item, dict):
                # try common keys
                code = (
                    item.get("code")
                    or item.get("snippet")
                    or item.get("text")
                )
                if isinstance(code, str):
                    snippets.append(code)
                else:
                    # fallback: stringify dict
                    snippets.append(json.dumps(item, ensure_ascii=False))
            else:
                snippets.append(str(item))

    return snippets


def _ensure_multiline_text(field: Any) -> str:
    """
    Normalize fields that may be either list[str] or str into a nice multiline string.
    """
    if field is None:
        return ""
    if isinstance(field, str):
        return field
    if isinstance(field, list):
        return "\n".join(str(x) for x in field)
    return str(field)


def make_examples(entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    req_id = entry.get("req_id", "UNKNOWN")
    desc = entry.get("req_description", "")

    insecure_snips = _extract_snippets(entry.get("insecure_examples"))
    secure_snips = _extract_snippets(entry.get("secure_examples"))
    threats_text = _ensure_multiline_text(entry.get("threats_mitigated"))
    verify_text = _ensure_multiline_text(entry.get("verification_steps"))
    mistakes_text = _ensure_multiline_text(entry.get("common_mistakes"))

    examples: List[Dict[str, Any]] = []

    # ---------------------------------------------------------
    # 1. Explanation Task
    # ---------------------------------------------------------
    explanation = entry.get("explanation", "")
    examples.append({
        "instruction": f"Explain the OWASP ASVS requirement {req_id} in detail.",
        "input": desc,
        "output": explanation,
    })

    # ---------------------------------------------------------
    # 2. Secure vs Insecure Code Review
    # ---------------------------------------------------------
    if insecure_snips and secure_snips:
        bad = "\n".join(insecure_snips)
        good = "\n".join(secure_snips)
        examples.append({
            "instruction": (
                f"Identify all security issues in the following insecure code "
                f"and rewrite it to comply with ASVS requirement {req_id}."
            ),
            "input": bad,
            "output": good + "\n\nExplanation:\n" + explanation,
        })

    # ---------------------------------------------------------
    # 3. Compliance Classification (secure)
    # ---------------------------------------------------------
    if secure_snips:
        examples.append({
            "instruction": (
                f"Is the following code compliant with ASVS requirement {req_id}? "
                "Answer yes or no and explain briefly."
            ),
            "input": secure_snips[0],
            "output": "Yes, it is compliant.\n\n" + explanation,
        })

    # ---------------------------------------------------------
    # 4. Compliance Classification (insecure)
    # ---------------------------------------------------------
    if insecure_snips:
        examples.append({
            "instruction": (
                f"Is the following code compliant with ASVS requirement {req_id}? "
                "Answer yes or no and explain briefly."
            ),
            "input": insecure_snips[0],
            "output": "No, it is not compliant.\n\n" + explanation,
        })

    # ---------------------------------------------------------
    # 5. Threat Model Reasoning
    # ---------------------------------------------------------
    if threats_text:
        examples.append({
            "instruction": f"What threats does ASVS requirement {req_id} mitigate?",
            "input": desc,
            "output": threats_text,
        })

    # ---------------------------------------------------------
    # 6. Verification Checklist
    # ---------------------------------------------------------
    if verify_text:
        examples.append({
            "instruction": (
                f"Provide a step-by-step secure code review checklist to verify "
                f"ASVS requirement {req_id}."
            ),
            "input": desc,
            "output": verify_text,
        })

    # ---------------------------------------------------------
    # 7. Common Mistakes
    # ---------------------------------------------------------
    if mistakes_text:
        examples.append({
            "instruction": (
                f"What are common developer mistakes that violate ASVS "
                f"requirement {req_id}?"
            ),
            "input": desc,
            "output": mistakes_text,
        })

    return examples


def main():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    count_entries = 0
    count_examples = 0

    with ENRICHED_PATH.open("r", encoding="utf-8") as inf, \
         OUT_PATH.open("w", encoding="utf-8") as outf:

        for line in inf:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            sft_examples = make_examples(entry)

            for ex in sft_examples:
                outf.write(json.dumps(ex, ensure_ascii=False) + "\n")
                count_examples += 1

            count_entries += 1

    print(f"[DONE] Converted {count_entries} ASVS rows → {count_examples} Alpaca SFT examples")
    print(f"Saved to {OUT_PATH}")


if __name__ == "__main__":
    main()
