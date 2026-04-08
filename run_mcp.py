"""Standalone MCP server launcher — no PYTHONPATH env needed.

Usage (from WSL or Windows):
    python run_mcp.py graph_mcp   [BOUNCE_INV_ID set in env]
    python run_mcp.py cti_mcp
"""
import sys
import os

# Add project root to sys.path regardless of cwd or PYTHONPATH
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if len(sys.argv) < 2:
    print("Usage: python run_mcp.py <graph_mcp|cti_mcp>", file=sys.stderr)
    sys.exit(1)

module_name = sys.argv[1]
import importlib
mod = importlib.import_module(f"backend.mcp_servers.{module_name}")
mod.mcp.run()
