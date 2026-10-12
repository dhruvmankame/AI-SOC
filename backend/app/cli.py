from __future__ import annotations

import argparse
import asyncio

from .db import close_db, fetch_all, open_db
from .graph import investigate_streaming


async def run_one(incident_id: str) -> None:
    def progress(event: dict) -> None:
        print(f"{incident_id}: {event}")

    await investigate_streaming(incident_id, progress, auto_report=True)


async def main() -> None:
    parser = argparse.ArgumentParser(description="Run AI-SOC investigations from Python.")
    parser.add_argument("incident_id", nargs="?")
    args = parser.parse_args()

    await open_db()
    try:
        if args.incident_id:
            await run_one(args.incident_id)
        else:
            rows = await fetch_all("select incident_id::text from incidents order by created_at")
            for row in rows:
                await run_one(row["incident_id"])
    finally:
        await close_db()


if __name__ == "__main__":
    asyncio.run(main())
