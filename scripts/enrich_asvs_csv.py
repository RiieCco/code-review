#!/usr/bin/env python3

import csv
import json
import os
from pathlib import Path
from openai import OpenAI

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "data" / "raw" / "ASVS" / "ASVS5_0.csv"
OUT_PATH = ROOT / "data" / "processed" / "asvs.enriched.jsonl"

client = OpenAI(api_key="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")

SYSTEM_PROMPT = """
You are a senior application security architect.

Given an OWASP ASVS requirement (as structured CSV fields), produce a JSON object with deep enrichment:

Fields to include:
- chapter_id
- chapter_name
- section_id
- section_name
- req_id
- req_description
- level: ASVS Level (L)
- explanation: What this requirement means, in detail
- threats_mitigated: list of threats this requirement helps prevent
- insecure_examples: 1-2 code snippets that violate the requirement
- secure_examples: corrected secure versions
- verification_steps: a checklist for secure code review
- common_mistakes: mistakes developers routinely make related to this requirement
- related_cwe: list of CWE IDs (infer if needed)
- related_capec: list of CAPEC attack patterns (infer if needed)
- attack_flow: how an attacker exploits violations of this requirement

Return ONLY valid JSON (NO markdown, NO commentary).
"""

def enrich_row(row):
    user_prompt = f"""
ASVS CSV Row:
- chapter_id: {row['chapter_id']}
- chapter_name: {row['chapter_name']}
- section_id: {row['section_id']}
- section_name: {row['section_name']}
- req_id: {row['req_id']}
- req_description: {row['req_description']}
- level: {row['L']}

Generate the enriched JSON object.
"""

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.4
    )

    txt = resp.choices[0].message.content.strip()

    # In case model wraps JSON in ``` fences
    if txt.startswith("```"):
        txt = txt.strip("`").strip()

    try:
        return json.loads(txt)
    except Exception as e:
        print("\n[ERROR] Failed to parse JSON:")
        print(txt)
        print(e)
        return None


def main():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(CSV_PATH, newline="", encoding="utf-8") as csvf, OUT_PATH.open("w", encoding="utf-8") as outf:
        reader = csv.DictReader(csvf)
        count = 0

        for row in reader:
            enriched = enrich_row(row)
            if enriched:
                outf.write(json.dumps(enriched, ensure_ascii=False) + "\n")
                count += 1
                print(f"[OK] Enriched requirement {row['req_id']}")

    print(f"\n[DONE] Enriched {count} ASVS requirements → {OUT_PATH}")


if __name__ == "__main__":
    main()
