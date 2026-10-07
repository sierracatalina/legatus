"""Verify pinned PCP bytes; optionally compare against an upstream git checkout."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def check(upstream=None):
    pin = json.loads((ROOT / "schemas" / "pcp-source.json").read_text())
    actual_files = {path.name for path in (ROOT / "schemas").glob("pcp*.schema.json")}
    if actual_files != set(pin["files"]):
        raise ValueError("PCP schema inventory differs from the pin")
    for name, expected in pin["files"].items():
        data = (ROOT / "schemas" / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("PCP schema drift: " + name)
        if upstream is not None:
            source = subprocess.check_output(["git", "-C", str(upstream), "show",
                                              pin["commit"] + ":schemas/" + name])
            if data != source:
                raise ValueError("PCP upstream byte mismatch: " + name)
    return len(pin["files"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path)
    args = parser.parse_args()
    print(f"PCP schema pin verified: {check(args.upstream)} files")
