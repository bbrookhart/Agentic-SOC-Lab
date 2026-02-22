from __future__ import annotations
import argparse, hashlib, json, os
from datetime import datetime, timezone
from pathlib import Path

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", required=True, help="Path to JSONL logs")
    ap.add_argument("--alerts", required=True, help="Path to alerts JSONL")
    ap.add_argument("--outdir", required=True, help="Output evidence directory")
    args = ap.parse_args()

    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)

    logs = Path(args.logs)
    alerts = Path(args.alerts)

    hashes = {
        str(logs.name): sha256_file(logs),
        str(alerts.name): sha256_file(alerts),
    }

    (out / logs.name).write_bytes(logs.read_bytes())
    (out / alerts.name).write_bytes(alerts.read_bytes())

    (out / "hashes.txt").write_text(
        "\n".join([f"{v}  {k}" for k, v in hashes.items()]) + "\n",
        encoding="utf-8",
    )

    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
        "artifacts": [
            {"name": logs.name, "sha256": hashes[logs.name]},
            {"name": alerts.name, "sha256": hashes[alerts.name]},
            {"name": "hashes.txt", "sha256": sha256_file(out / "hashes.txt")},
        ],
        "notes": "v1 evidence pack (hashes only). Add signing in v2.",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Evidence pack written to {out}")

if __name__ == "__main__":
    main()
