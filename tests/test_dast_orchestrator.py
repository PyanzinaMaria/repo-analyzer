from __future__ import annotations

from app.dast.config import DastConfig
from app.dast.orchestrator import DastOrchestrator
from app.dast.store import DastStore
from app.languages.python.handler import PythonHandler
from app.languages.registry import LanguageRegistry
from app.models.dast import DastScanCreate
from app.models.finding import Finding, LanguageAnalysis, Severity


class TrackingPython(PythonHandler):
    def __init__(self) -> None:
        super().__init__(enabled=True)
        self.dast_calls = 0

    def detect_runtime(self, target_url, fingerprint):  # noqa: ANN001
        return True

    def analyze_dast(self, target_url, job_ctx=None):  # noqa: ANN001
        self.dast_calls += 1
        return LanguageAnalysis(
            language=self.id,
            findings=[
                Finding(
                    id="py-1",
                    title="python hook",
                    description="from analyze_dast",
                    severity=Severity.info,
                    source="dast-python",
                    language=self.id,
                )
            ],
            meta={"dast": "ok"},
        )


def test_orchestrator_uses_enabled_language_hooks(tmp_data_dir, monkeypatch) -> None:
    handler = TrackingPython()
    registry = LanguageRegistry(handlers=[handler])
    handler.enabled = True

    cfg = DastConfig(enabled=True, allow_private_targets=True, timeout_seconds=30)
    orch = DastOrchestrator(store=DastStore(), registry=registry, cfg=cfg)

    monkeypatch.setattr(
        "app.dast.orchestrator.run_preflight",
        lambda *a, **k: (
            [
                Finding(
                    id="pf-1",
                    title="missing header",
                    description="x",
                    severity=Severity.medium,
                    source="dast-preflight",
                    language="http",
                )
            ],
            {
                "ok": True,
                "status_code": 200,
                "fingerprint": {"hints": ["fastapi"], "server": "uvicorn", "headers": {}},
            },
        ),
    )
    monkeypatch.setattr(
        "app.dast.orchestrator.run_zap_baseline",
        lambda *a, **k: ([], {"status": "skipped", "reason": "mocked"}),
    )
    monkeypatch.setattr(
        "app.dast.orchestrator.validate_target_url",
        lambda url, cfg: url,
    )

    result = orch.run_to_result(
        DastScanCreate(target_url="http://127.0.0.1:8001/"),
        scan_id="abc123",
    )
    assert handler.dast_calls == 1
    assert result.meta["dast"]["languages_matched"] == ["python"]
    assert any(f.source == "dast-python" for f in result.findings)
    assert any(f.source == "dast-preflight" and f.language == "python" for f in result.findings)


def test_disabled_language_hook_not_called(tmp_data_dir, monkeypatch) -> None:
    handler = TrackingPython()
    registry = LanguageRegistry(handlers=[handler])
    handler.enabled = False

    cfg = DastConfig(enabled=True, allow_private_targets=True)
    orch = DastOrchestrator(store=DastStore(), registry=registry, cfg=cfg)
    monkeypatch.setattr(
        "app.dast.orchestrator.run_preflight",
        lambda *a, **k: (
            [],
            {"ok": True, "fingerprint": {"hints": ["fastapi"], "headers": {}}},
        ),
    )
    monkeypatch.setattr(
        "app.dast.orchestrator.run_zap_baseline",
        lambda *a, **k: ([], {"status": "skipped"}),
    )
    monkeypatch.setattr("app.dast.orchestrator.validate_target_url", lambda url, cfg: url)

    result = orch.run_to_result(DastScanCreate(target_url="http://127.0.0.1:8001/"))
    assert handler.dast_calls == 0
    assert result.meta["dast"]["languages_matched"] == []
