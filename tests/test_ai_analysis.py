from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from app.ai.client import OpenAICompatibleClient
from app.ai.config import AiSettings, is_ai_enabled
from app.ai.parser import parse_ai_findings
from app.ai.selector import select_files
from app.ai.service import run_ai_analysis
from app.core.config import get_settings
from app.models.finding import CodeInventory, Finding, Severity


def _ai_settings(**overrides) -> AiSettings:
    base = dict(
        enabled=True,
        provider="openai_compatible",
        base_url="https://example.test/v1",
        model="test-model",
        api_key="test-key",
        timeout_seconds=10,
        max_files=3,
        max_file_bytes=40000,
        max_findings=10,
    )
    base.update(overrides)
    return AiSettings(**base)


def _sample_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "auth_login.py").write_text(
        "PASSWORD = 'secret'\ndef login(u, p):\n    return p == PASSWORD\n",
        encoding="utf-8",
    )
    (root / "utils.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    (root / ".venv" / "lib").mkdir(parents=True)
    (root / ".venv" / "lib" / "x.py").write_text("x=1\n", encoding="utf-8")
    return root


def _mock_transport(payload: dict | str, status_code: int = 200) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if status_code >= 400:
            text = payload if isinstance(payload, str) else json.dumps(payload)
            return httpx.Response(status_code, text=text)
        if isinstance(payload, dict) and "choices" in payload:
            content = json.dumps(payload)
        elif isinstance(payload, dict):
            content = json.dumps(
                {"choices": [{"message": {"content": json.dumps(payload)}}]}
            )
        else:
            content = json.dumps(
                {"choices": [{"message": {"content": payload}}]}
            )
        return httpx.Response(
            200, content=content, headers={"content-type": "application/json"}
        )

    return httpx.MockTransport(handler)


def test_is_ai_enabled_requires_key_and_config(tmp_path, monkeypatch):
    cfg = tmp_path / "settings.yaml"
    cfg.write_text(
        "enabled_languages: [python]\nai:\n  enabled: true\n  model: m\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SETTINGS_PATH", str(cfg))
    # Empty, not deleted: a developer's real .env (picked up via env_file)
    # must not leak an API key into this test.
    monkeypatch.setenv("AI_API_KEY", "")
    monkeypatch.delenv("AI_ENABLED", raising=False)
    get_settings.cache_clear()

    assert is_ai_enabled() is False
    monkeypatch.setenv("AI_API_KEY", "k")
    get_settings.cache_clear()
    assert is_ai_enabled() is True
    assert is_ai_enabled(False) is False
    assert is_ai_enabled(True) is True


def test_selector_respects_max_files_and_exclude(tmp_path, monkeypatch):
    root = _sample_repo(tmp_path / "repo")
    cfg_path = tmp_path / "settings.yaml"
    cfg_path.write_text(
        "scan:\n  exclude_dirs: [.venv]\nai:\n  enabled: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("SETTINGS_PATH", str(cfg_path))
    get_settings.cache_clear()

    inv = CodeInventory(language="python", files_count=2, modules=["auth_login.py", "utils.py"])
    selected = select_files(root, [inv], _ai_settings(max_files=1))
    assert len(selected) == 1
    assert selected[0].rel_path == "auth_login.py"
    assert all(".venv" not in s.rel_path for s in selected)


def test_parser_maps_findings_and_drops_duplicates():
    existing = [
        Finding(
            id="b1",
            title="Hardcoded password",
            description="password in source",
            severity=Severity.high,
            cwe="CWE-798",
            file="auth_login.py",
            line=1,
            source="bandit",
            language="python",
        )
    ]
    raw = json.dumps(
        {
            "findings": [
                {
                    "title": "Hardcoded password",
                    "description": "same issue",
                    "severity": "high",
                    "cwe": "CWE-798",
                    "file": "auth_login.py",
                    "line": 1,
                    "remediation": "use env",
                },
                {
                    "title": "Missing rate limit",
                    "description": "login has no throttling",
                    "severity": "medium",
                    "file": "auth_login.py",
                    "line": 2,
                    "remediation": "add rate limiting",
                },
                {
                    "title": "Invented",
                    "description": "hallucination",
                    "severity": "high",
                    "file": "not_in_context.py",
                    "line": 1,
                },
            ]
        }
    )
    parsed = parse_ai_findings(
        raw,
        selected_paths={"auth_login.py"},
        existing_findings=existing,
        max_findings=10,
    )
    assert len(parsed) == 1
    assert parsed[0].source == "ai"
    assert parsed[0].title == "Missing rate limit"
    assert parsed[0].rule_id.startswith("AI-")


def test_run_ai_disabled_skips_without_http(tmp_path):
    root = _sample_repo(tmp_path / "repo")
    findings, meta = run_ai_analysis(
        root,
        [],
        [],
        enable_override=False,
        settings=_ai_settings(enabled=True, api_key="k"),
    )
    assert findings == []
    assert meta["status"] == "skipped"


def test_run_ai_missing_key_skips(tmp_path, monkeypatch):
    root = _sample_repo(tmp_path / "repo")
    cfg = tmp_path / "settings.yaml"
    cfg.write_text("ai:\n  enabled: true\n", encoding="utf-8")
    monkeypatch.setenv("SETTINGS_PATH", str(cfg))
    # Empty, not deleted: a developer's real .env (picked up via env_file)
    # must not leak an API key into this test.
    monkeypatch.setenv("AI_API_KEY", "")
    get_settings.cache_clear()

    findings, meta = run_ai_analysis(root, [], [])
    assert findings == []
    assert meta["status"] == "skipped"
    assert meta["error"] == "missing_api_key"


def test_run_ai_valid_json_returns_findings(tmp_path):
    root = _sample_repo(tmp_path / "repo")
    inv = CodeInventory(language="python", files_count=1, modules=["auth_login.py"])
    transport = _mock_transport(
        {
            "findings": [
                {
                    "title": "Hardcoded secret",
                    "description": "PASSWORD constant in source",
                    "severity": "high",
                    "cwe": "CWE-798",
                    "file": "auth_login.py",
                    "line": 1,
                    "remediation": "Load from environment",
                }
            ]
        }
    )
    findings, meta = run_ai_analysis(
        root,
        [],
        [inv],
        enable_override=True,
        transport=transport,
        settings=_ai_settings(),
    )
    assert meta["status"] == "completed"
    assert meta["files_sent"] >= 1
    assert len(findings) == 1
    assert findings[0].source == "ai"
    assert findings[0].file == "auth_login.py"


def test_run_ai_http_error_soft_fails(tmp_path):
    root = _sample_repo(tmp_path / "repo")
    inv = CodeInventory(language="python", files_count=1, modules=["auth_login.py"])
    transport = _mock_transport("boom", status_code=500)
    findings, meta = run_ai_analysis(
        root,
        [],
        [inv],
        enable_override=True,
        transport=transport,
        settings=_ai_settings(),
    )
    assert findings == []
    assert meta["status"] == "failed"
    assert "500" in (meta["error"] or "")


def test_run_ai_broken_json_then_repair(tmp_path):
    root = _sample_repo(tmp_path / "repo")
    inv = CodeInventory(language="python", files_count=1, modules=["auth_login.py"])
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            content = json.dumps(
                {"choices": [{"message": {"content": "not-json"}}]}
            )
        else:
            payload = {
                "findings": [
                    {
                        "title": "Hardcoded secret",
                        "description": "secret in code",
                        "severity": "high",
                        "file": "auth_login.py",
                        "line": 1,
                    }
                ]
            }
            content = json.dumps(
                {"choices": [{"message": {"content": json.dumps(payload)}}]}
            )
        return httpx.Response(200, content=content)

    findings, meta = run_ai_analysis(
        root,
        [],
        [inv],
        enable_override=True,
        transport=httpx.MockTransport(handler),
        settings=_ai_settings(),
    )
    assert calls["n"] == 2
    assert meta["status"] == "completed"
    assert len(findings) == 1


def test_client_chat_json_shape():
    transport = _mock_transport(
        {"choices": [{"message": {"content": '{"findings":[]}'}}]}
    )
    client = OpenAICompatibleClient(_ai_settings(), transport=transport)
    text = client.chat_json("hi")
    assert '"findings"' in text


def test_client_retries_empty_json_content_without_response_format():
    """Gateways occasionally answer json_object requests with empty content:
    the client must retry once without the format flag before failing."""
    calls: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        calls.append(body)
        if "response_format" in body:
            content = ""
        else:
            content = '{"findings": []}'
        return httpx.Response(
            200,
            content=json.dumps({"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}),
            headers={"content-type": "application/json"},
        )

    client = OpenAICompatibleClient(_ai_settings(), transport=httpx.MockTransport(handler))
    text = client.chat_json("hi")
    assert '"findings"' in text
    assert len(calls) == 2  # first with response_format, retry without
    assert "response_format" in calls[0] and "response_format" not in calls[1]


def test_client_raises_on_persistently_empty_content():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=json.dumps({"choices": [{"message": {"content": ""}, "finish_reason": "length"}]}),
            headers={"content-type": "application/json"},
        )

    client = OpenAICompatibleClient(_ai_settings(), transport=httpx.MockTransport(handler))
    with pytest.raises(Exception, match="Empty AI response content"):
        client.chat_json("hi")


def test_scan_endpoint_accepts_enable_ai_body(client, tmp_path, monkeypatch):
    sample = _sample_repo(tmp_path / "sample_repo")
    create = client.post(
        "/api/v1/projects",
        json={"source_type": "local_path", "local_path": str(sample), "name": "ai-sample"},
    )
    assert create.status_code == 201, create.text
    project_id = create.json()["id"]

    # Deterministic AI stub: the developer's real .env (AI_API_KEY via
    # env_file) must not leak into endpoint tests.
    import app.services.scan.orchestrator as orch_mod

    monkeypatch.setattr(
        orch_mod, "run_ai_analysis",
        lambda *a, **k: ([], {"enabled": True, "status": "skipped", "model": None,
                              "files_sent": 0, "findings_count": 0, "error": "test_stub"}),
    )
    monkeypatch.setenv("AI_API_KEY", "")
    get_settings.cache_clear()
    from app.api import deps

    deps.get_scan_orchestrator.cache_clear()

    scan = client.post(
        f"/api/v1/projects/{project_id}/scans",
        json={"enable_ai": True},
    )
    assert scan.status_code == 201, scan.text
    assert scan.json()["status"] == "completed"

    result = client.get(
        f"/api/v1/projects/{project_id}/scans/{scan.json()['id']}/result"
    )
    assert result.status_code == 200
    meta_ai = result.json()["meta"]["ai"]
    assert meta_ai["status"] == "skipped"
    assert meta_ai["error"] == "test_stub"  # AI call stubbed in this test

    security_md = client.get(
        f"/api/v1/projects/{project_id}/scans/{scan.json()['id']}/reports/security",
        params={"format": "markdown"},
    )
    assert security_md.status_code == 200
    assert "Отчёт по уязвимостям" in security_md.text  # template no longer has an AI section
