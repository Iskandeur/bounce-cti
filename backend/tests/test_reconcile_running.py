"""Startup reconciliation of zombie 'running' investigations (temp DB)."""
import backend.graph_store as gs


def test_reconcile_orphaned_running(tmp_path, monkeypatch):
    monkeypatch.setattr(gs, "DB_PATH", str(tmp_path / "t.db"))
    gs.init_db()
    a = gs.create_investigation("domain", "a.com", user_id=1)
    b = gs.create_investigation("domain", "b.com", user_id=1)
    done = gs.create_investigation("domain", "c.com", user_id=1)
    gs.set_status(a, "running")
    gs.set_status(b, "running")
    gs.set_status(done, "done")

    n = gs.reconcile_orphaned_running()
    assert n == 2

    with gs.conn() as c:
        st = {r["id"]: r["status"] for r in
              c.execute("SELECT id, status FROM investigations").fetchall()}
    assert st[a] == "error: interrupted"
    assert st[b] == "error: interrupted"
    assert st[done] == "done"          # terminal rows untouched
    # idempotent: a second pass finds nothing
    assert gs.reconcile_orphaned_running() == 0
