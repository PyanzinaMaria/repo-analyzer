from __future__ import annotations

"""Minimal MCP (Model Context Protocol) server over stdio for the pentest tools.

Lets any MCP host (Claude Code, Cursor, our own agent) drive the same tool layer:

    PENTEST_TARGET_URL=http://127.0.0.1:5001 PENTEST_ALLOW_PRIVATE=1 \
        python -m app.dast.agent.mcp_server

Supported methods: initialize, tools/list, tools/call, ping; notifications are
acknowledged silently. No third-party MCP SDK is required.
"""
import json
import os
import sys
from typing import Any

from app.dast.agent.config import load_pentest_config
from app.dast.agent.target import TargetClient
from app.dast.agent.tools import AgentState, ToolRegistry


def _result(msg_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


def _error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def main() -> int:
    target = os.environ.get("PENTEST_TARGET_URL")
    if not target:
        print("PENTEST_TARGET_URL is required", file=sys.stderr)
        return 2
    cfg = load_pentest_config({
        "allow_private_targets": os.environ.get("PENTEST_ALLOW_PRIVATE", "1") == "1",
    })
    state = AgentState(client=TargetClient(target, cfg), cfg=cfg)
    tools = ToolRegistry(state)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            print(json.dumps(_error(None, -32700, "parse error")), flush=True)
            continue
        method = msg.get("method")
        msg_id = msg.get("id")

        if msg_id is None:  # notification
            continue
        if method == "initialize":
            reply = _result(msg_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "fstec-pentest-agent", "version": "0.1.0"},
            })
        elif method == "ping":
            reply = _result(msg_id, {})
        elif method == "tools/list":
            reply = _result(msg_id, {"tools": [
                {"name": t["name"], "description": t["description"],
                 "inputSchema": t["input_schema"]}
                for t in tools.schemas()
            ]})
        elif method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            out = tools.call(name, args)
            reply = _result(msg_id, {"content": [
                {"type": "text", "text": json.dumps(out, ensure_ascii=False)}
            ]})
        else:
            reply = _error(msg_id, -32601, f"method not found: {method}")
        print(json.dumps(reply, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
