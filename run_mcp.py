"""Standalone MCP server launcher — no PYTHONPATH env needed.

Usage (from WSL or Windows):
    python run_mcp.py graph_mcp   [BOUNCE_INV_ID set in env]
    python run_mcp.py cti_mcp
"""
import sys
import os
import time
import traceback

# Add project root to sys.path regardless of cwd or PYTHONPATH
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if len(sys.argv) < 2:
    print("Usage: python run_mcp.py <graph_mcp|cti_mcp>", file=sys.stderr)
    sys.exit(1)

module_name = sys.argv[1]

# Trace startup to a per-server log file so we can debug claude MCP timeouts.
log_path = os.path.join(PROJECT_ROOT, "data", f"mcp-launcher-{module_name}.log")
def _log(msg):
    try:
        with open(log_path, "a") as f:
            f.write(f"[{time.time():.2f}] pid={os.getpid()} {msg}\n")
    except Exception:
        pass

_log(f"start argv={sys.argv}")
try:
    import importlib
    t0 = time.time()
    mod = importlib.import_module(f"backend.mcp_servers.{module_name}")
    _log(f"imported in {time.time()-t0:.1f}s, calling mcp.run()")
    mod.mcp.run()
    _log("mcp.run() returned cleanly")
except SystemExit as e:
    _log(f"SystemExit code={e.code}")
    raise
except BaseException as e:
    _log(f"FATAL {type(e).__name__}: {e}\n{traceback.format_exc()}")
    raise
