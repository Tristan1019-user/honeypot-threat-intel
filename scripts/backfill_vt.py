#!/usr/bin/env python3
"""
backfill_vt.py — enrich existing malware samples with VirusTotal data.

Run once after setting VT_API_KEY to retroactively enrich already-stored
malware sample hashes. Respects the free-tier rate limit (4 req/min).

Usage (from CT 103):
    docker exec -e VT_API_KEY=<key> threat-intel-api \
        python /srv/app/../scripts/backfill_vt.py
"""
import asyncio
import os
import sys

sys.path.insert(0, "/srv")

async def main() -> None:
    from app import database as db
    from app.enrichment import enrich_malware_vt, VT_API_KEY

    if not VT_API_KEY:
        print("ERROR: VT_API_KEY not set", file=sys.stderr)
        sys.exit(1)

    await db.init_pool()

    try:
        rows = await db._fetch(
            "SELECT sha256, vt_known FROM malware_samples WHERE vt_enriched_at IS NULL"
        )

        if not rows:
            print("No samples pending VT enrichment.")
            return

        print(f"Found {len(rows)} samples pending VT enrichment.")

        enriched = 0
        for i, row in enumerate(rows):
            sha256 = row["sha256"]
            print(f"[{i+1}/{len(rows)}] {sha256[:24]}...", end=" ", flush=True)
            vt_data = await enrich_malware_vt(sha256)
            if vt_data:
                await db.update_malware_vt(sha256, vt_data)
                known = vt_data.get("vt_known")
                if known:
                    ratio = vt_data.get("vt_detection_ratio", "?/?")
                    families = vt_data.get("vt_malware_families", [])
                    print(f"✓ {ratio} detections, families: {families}")
                else:
                    print("✓ not in VT")
                enriched += 1
            else:
                print("⚠ VT unavailable — skipped (will retry next run)")

        print(f"\nDone: {enriched}/{len(rows)} enriched.")
    finally:
        await db.close_pool()

if __name__ == "__main__":
    asyncio.run(main())
