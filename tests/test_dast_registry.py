from __future__ import annotations

from app.languages.base import LanguageHandler
from app.languages.python.handler import PythonHandler
from app.languages.registry import LanguageRegistry
from app.models.finding import LanguageAnalysis


class StubCsHandler(LanguageHandler):
    id = "csharp"
    display_name = "C#"
    extensions = (".cs",)

    def detect(self, root):  # noqa: ANN001
        return False

    def analyze(self, root, job_ctx=None):  # noqa: ANN001
        return LanguageAnalysis(language=self.id)

    def detect_runtime(self, target_url, fingerprint):  # noqa: ANN001
        return "aspnet" in (fingerprint.get("hints") or [])

    def analyze_dast(self, target_url, job_ctx=None):  # noqa: ANN001
        return LanguageAnalysis(
            language=self.id,
            findings=[],
            meta={"dast": "stub-called"},
        )


def test_disabled_language_not_in_enabled() -> None:
    registry = LanguageRegistry(
        handlers=[
            PythonHandler(enabled=True),
            StubCsHandler(enabled=False),
        ]
    )
    # Force flags regardless of yaml
    registry.get("python").enabled = True
    registry.get("csharp").enabled = False
    assert [h.id for h in registry.enabled()] == ["python"]


def test_python_detect_runtime_from_hints() -> None:
    handler = PythonHandler(enabled=True)
    assert handler.detect_runtime("http://x/", {"hints": ["fastapi", "uvicorn"]})
    assert not handler.detect_runtime("http://x/", {"hints": ["express"], "server": "nginx"})


def test_enabled_csharp_would_match_aspnet() -> None:
    cs = StubCsHandler(enabled=True)
    assert cs.detect_runtime("http://x/", {"hints": ["aspnet"]})
    analysis = cs.analyze_dast("http://x/")
    assert analysis.meta["dast"] == "stub-called"
