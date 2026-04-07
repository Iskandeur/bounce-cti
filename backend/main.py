"""FastAPI entry point: REST + WebSocket for live graph updates."""
import asyncio
import json
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import graph_store as gs
from .agent_runner import run_investigation

app = FastAPI(title="Bounce-CTI")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class StartReq(BaseModel):
    seed_type: str  # domain | ip | hash
    seed_value: str


@app.post("/api/investigations")
async def start(req: StartReq):
    inv_id = gs.create_investigation(req.seed_type, req.seed_value)
    asyncio.create_task(run_investigation(inv_id, req.seed_type, req.seed_value))
    return {"id": inv_id}


@app.get("/api/investigations")
def list_inv():
    return gs.list_investigations()


@app.get("/api/investigations/{inv_id}/graph")
def graph(inv_id: str):
    return gs.get_graph(inv_id)


@app.delete("/api/investigations/{inv_id}")
def delete_inv(inv_id: str):
    gs.delete_investigation(inv_id)
    return {"ok": True}


@app.post("/api/investigations/{inv_id}/rerun")
async def rerun(inv_id: str):
    """Clear the graph and restart the agent on the same seed."""
    with gs.conn() as c:
        row = c.execute("SELECT seed_type, seed_value FROM investigations WHERE id=?", (inv_id,)).fetchone()
    if not row:
        return {"error": "not found"}
    gs.clear_investigation(inv_id)
    with gs.conn() as c:
        c.execute("UPDATE investigations SET status='running' WHERE id=?", (inv_id,))
    asyncio.create_task(run_investigation(inv_id, row["seed_type"], row["seed_value"]))
    return {"ok": True}


@app.websocket("/ws/{inv_id}")
async def ws(websocket: WebSocket, inv_id: str):
    await websocket.accept()
    last = 0
    # send initial snapshot
    await websocket.send_json({"kind": "snapshot", "graph": gs.get_graph(inv_id)})
    try:
        while True:
            events = gs.get_events_since(inv_id, last)
            for e in events:
                last = max(last, e.get("_id", last))
                await websocket.send_json(e)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return


# Serve frontend build if present
DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
if DIST.exists():
    app.mount("/", StaticFiles(directory=str(DIST), html=True), name="frontend")
