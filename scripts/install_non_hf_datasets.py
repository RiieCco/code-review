#!/usr/bin/env python3

import requests
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "datasets" / "raw"

def ensure(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def fetch(url: str, dest: Path):
    print(f"Downloading: {url}")
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    dest.write_bytes(resp.content)
    print(f"Saved → {dest}")

def install_asvs():
    folder = RAW / "asvs"
    ensure(folder)

    base = "https://raw.githubusercontent.com/OWASP/ASVS/v5.0/5.0/en/"
    files = [
        "0x11-V1-Architecture.md",
        "0x12-V2-Authentication.md",
        "0x13-V3-Session_Management.md",
        "0x14-V4-Access_Control.md",
        "0x15-V5-Validation_Sanitization_Encoding.md",
        "0x16-V6-Stored_Cryptography.md",
        "0x17-V7-Error_Handling_and_Logging.md",
        "0x18-V8-Data_Protection.md",
        "0x19-V9-Communications.md",
        "0x1A-V10-Malicious_Code.md",
        "0x1B-V11-Business_Logic.md",
        "0x1C-V12-File_and_Resources.md",
        "0x1D-V13-API_and_Web_Services.md",
        "0x1E-V14-Configuration.md",
    ]

    for fname in files:
        url = base + fname
        dest = folder / fname
        try:
            fetch(url, dest)
        except Exception as e:
            print(f"[WARN] Failed downloading {fname}: {e}")

def main():
    ensure(RAW)
    install_asvs()
    print("\n[DONE] ASVS downloaded.")

if __name__ == "__main__":
    main()
