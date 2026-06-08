from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def summarize_mcp_message(message: dict[str, Any], *, max_raw_length: int = 256) -> dict[str, Any]:
    method = str(message.get("method") or "")
    params = dict(message.get("params") or {})
    raw = json.dumps(message, sort_keys=True)
    if method == "tools/call":
        kind = "tool_call"
        tool_name = str(params.get("name") or "")
    elif method == "tools/list":
        kind = "tools_list"
        tool_name = None
    else:
        kind = "jsonrpc"
        tool_name = None
    preview = raw[:max_raw_length]
    return {
        "kind": kind,
        "method": method,
        "tool_name": tool_name,
        "id": message.get("id"),
        "raw_content_preview": preview,
        "raw_content_length": len(raw),
        "raw_content_folded": len(raw) > len(preview),
        "content_note": "MCP JSON-RPC message folded/truncated for audit display",
    }


def transparent_broker_step(message: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    return message, {"mode": "transparent", "summary": summarize_mcp_message(message)}


def run_stdio_broker(*, input_path: Path, output_path: Path, transcript_path: Path, max_raw_length: int = 256) -> dict[str, Any]:
    messages = 0
    tool_calls = 0
    output_path.parent.mkdir(parents=True, exist_ok=True)
    transcript_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open("r", encoding="utf-8") as source, output_path.open("w", encoding="utf-8") as sink, transcript_path.open("w", encoding="utf-8") as transcript:
        for line in source:
            if not line.strip():
                sink.write(line)
                continue
            message = json.loads(line)
            _forwarded, evidence = transparent_broker_step(message)
            evidence["summary"] = summarize_mcp_message(message, max_raw_length=max_raw_length)
            sink.write(line)
            transcript.write(json.dumps(evidence, ensure_ascii=False, sort_keys=True) + "\n")
            messages += 1
            if evidence.get("summary", {}).get("kind") == "tool_call":
                tool_calls += 1
    return {
        "schema_version": "invart.mcp_stdio_broker.v0.17",
        "status": "pass",
        "input": str(input_path),
        "output": str(output_path),
        "transcript": str(transcript_path),
        "summary": {"messages": messages, "tool_calls": tool_calls},
    }
