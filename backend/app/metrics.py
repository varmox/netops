"""Read-only Prometheus access for the web UI's own dashboards (behind the login like the rest of /api)."""
import asyncio
import os
import time

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090").rstrip("/")
MAX_POINTS = 400

router = APIRouter(prefix="/api/metrics")


class Query(BaseModel):
    q: str
    minutes: int | None = None     # set: range query over the last N minutes; unset: instant value
    points: int = 120


class Batch(BaseModel):
    queries: dict[str, Query]


def _series(result: list[dict], ranged: bool) -> list[dict]:
    out = []
    for r in result:
        labels = {k: v for k, v in r["metric"].items() if k not in ("instance", "job")}
        if ranged:
            out.append({"labels": labels, "values": [[float(t), float(v)] for t, v in r["values"]]})
        else:
            out.append({"labels": labels, "value": float(r["value"][1])})
    return out


async def _run(client: httpx.AsyncClient, q: Query) -> list[dict] | dict:
    if q.minutes:
        end = time.time()
        points = max(10, min(q.points, MAX_POINTS))
        step = max(15, int(q.minutes * 60 / points))
        r = await client.get(PROMETHEUS_URL + "/api/v1/query_range",
                             params={"query": q.q, "start": end - q.minutes * 60, "end": end, "step": step})
    else:
        r = await client.get(PROMETHEUS_URL + "/api/v1/query", params={"query": q.q})
    body = r.json()
    if body.get("status") != "success":
        return {"error": body.get("error", "query failed")}
    return _series(body["data"]["result"], bool(q.minutes))


@router.post("/batch")
async def batch(b: Batch):
    if len(b.queries) > 40:
        raise HTTPException(400, "at most 40 queries per batch")
    async with httpx.AsyncClient(timeout=20) as client:
        results = await asyncio.gather(*(_run(client, q) for q in b.queries.values()), return_exceptions=True)
    return {k: (v if not isinstance(v, Exception) else {"error": str(v)}) for k, v in zip(b.queries, results)}
