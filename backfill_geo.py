#!/usr/bin/env python3
"""Backfill geo data (ASN, org, country, cloud_provider) for existing sessions."""
import asyncio
import json
import sys
import os

# Add app to path
sys.path.insert(0, os.path.dirname(__file__))

from app.enrichment import enrich_ip_geo, extract_observed_features, CLASSIFIER_VERSION
from app import database as db


async def backfill():
    os.environ.setdefault("DATABASE_PATH", "/data/threat_intel.db")
    await db.init_db()

    conn = await db.get_db()
    try:
        # Get all sessions missing geo data
        rows = await conn.execute_fetchall(
            "SELECT id, src_ip, raw_session FROM sessions WHERE (country IS NULL OR country = '') ORDER BY timestamp_start"
        )
        print(f"Found {len(rows)} sessions to backfill geo data")

        # Deduplicate IPs to minimize API calls
        ip_cache = {}
        for row in rows:
            ip = row[1]
            if ip not in ip_cache:
                geo = await enrich_ip_geo(ip)
                ip_cache[ip] = geo
                if geo.get("country"):
                    print(f"  {ip} -> {geo.get('country')} / {geo.get('asn')} / {geo.get('org','')[:30]}")
                else:
                    print(f"  {ip} -> no geo data")
                # Rate limit: ipwho.is allows ~10k/month free
                await asyncio.sleep(0.2)

        # Update sessions
        updated = 0
        for row in rows:
            sid, ip, raw_session = row[0], row[1], row[2]
            geo = ip_cache.get(ip, {})
            if not geo:
                continue

            # Also backfill observed_features if missing
            features_json = None
            try:
                raw = json.loads(raw_session) if raw_session else {}
                features = extract_observed_features(raw)
                features["classification_method"] = "rule_based"
                features["classifier_version"] = CLASSIFIER_VERSION
                features["model"] = None
                features["prompt_hash"] = None
                features_json = json.dumps(features)
            except Exception:
                pass

            await conn.execute(
                """UPDATE sessions SET asn=?, org=?, country=?, cloud_provider=?, observed_features=COALESCE(observed_features, ?)
                   WHERE id=?""",
                (geo.get("asn"), geo.get("org"), geo.get("country"), geo.get("cloud_provider"), features_json, sid),
            )
            updated += 1

        await conn.commit()
        print(f"Updated {updated} sessions")
        print(f"Unique IPs enriched: {len(ip_cache)}")
        print(f"Countries found: {len(set(g.get('country','') for g in ip_cache.values() if g.get('country')))}")

    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(backfill())
