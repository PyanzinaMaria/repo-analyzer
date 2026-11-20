"""API and page smoke tests over the full submission/serve flow."""

from __future__ import annotations

import re
import zipfile


def make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_index_renders_form_and_rules(client):
    c, _, _ = client
    r = c.get("/")
    assert r.status_code == 200
    assert "Отправка репозитория на аудит" in r.text
    assert "/static/css/theme.css" in r.text
    assert "Правила загрузки" in r.text


def test_disclaimer_banner_rendered(client, demo_scan):
    """Advisory banner: results are recommendations with a possible
    false-negative rate; shown on the submission page and above artifacts."""
    c, _, _ = client
    index = c.get("/")
    assert "рекомендательный характер" in index.text
    assert "false negatives" in index.text

    scan = c.get(f"/scan/{demo_scan}")
    assert scan.status_code == 200
    assert "рекомендательный характер" in scan.text


def test_link_submission_creates_scan_and_queue_job(client):
    c, settings, data_dir = client
    r = c.post(
        "/api/scans",
        data={"source_kind": "link", "repo_url": "https://github.com/owner/repo"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    scan_id = r.headers["location"].rsplit("/", 1)[-1]

    assert (data_dir / "uploads" / scan_id / "scan.json").is_file()
    queue_files = list((data_dir / "queue").glob("*.json"))
    assert len(queue_files) == 1
    assert scan_id in queue_files[0].name

    status = c.get(f"/api/scans/{scan_id}/status").json()
    assert status["stages"][0] == {"name": "intake", "state": "ok"}
    assert status["source"]["url"] == "https://github.com/owner/repo"


def test_submission_carries_options_to_queue_job(client):
    """Chosen methods/formats ride the queue job for the producer."""
    import json

    c, _, data_dir = client
    r = c.post(
        "/api/scans",
        data={
            "source_kind": "link",
            "repo_url": "https://github.com/owner/repo",
            "methods": ["sast", "llm_agentic"],
            "formats": ["pdf", "md"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    scan_id = r.headers["location"].rsplit("/", 1)[-1]

    job = json.loads((data_dir / "queue" / f"{scan_id}.json").read_text(encoding="utf-8"))
    assert job["options"] == {
        "methods": ["sast", "llm_agentic"],
        "formats": ["pdf", "md"],
    }
    status = c.get(f"/api/scans/{scan_id}/status").json()
    assert status["options"]["methods"] == ["sast", "llm_agentic"]


def test_submission_without_choices_inherits_config_defaults(client):
    """Defaults chain: absent/empty choices fall back to the YAML defaults."""
    import json

    c, _, data_dir = client
    r = c.post(
        "/api/scans",
        data={"source_kind": "link", "repo_url": "https://github.com/owner/repo"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    scan_id = r.headers["location"].rsplit("/", 1)[-1]

    job = json.loads((data_dir / "queue" / f"{scan_id}.json").read_text(encoding="utf-8"))
    # model is absent: the select stays hidden while methods=[sast], so the
    # producer inherits the analyzer-side default model.
    assert job["options"] == {"methods": ["sast"], "formats": ["html"]}


def test_submission_rejects_unavailable_method(client):
    """Planned methods are rejected even on direct API posts."""
    c, _, _ = client
    r = c.post(
        "/api/scans",
        data={
            "source_kind": "link",
            "repo_url": "https://github.com/owner/repo",
            "methods": ["sast", "pentest"],
            "formats": ["md"],
        },
    )
    assert r.status_code == 200
    assert "недоступен" in r.text


def test_index_renders_analysis_and_format_choices(client):
    import re

    c, _, _ = client
    r = c.get("/")
    assert r.status_code == 200
    assert 'name="methods"' in r.text
    assert 'value="dast"' in r.text
    assert 'value="pentest"' in r.text and "запланировано" in r.text
    # DAST checkbox itself must not be disabled (pentest still is).
    dast_input = re.search(r'<input[^>]*value="dast"[^>]*>', r.text)
    assert dast_input is not None and "disabled" not in dast_input.group(0)
    assert 'name="formats"' in r.text
    assert set(re.findall(r'<input[^>]*name="formats"[^>]*value="([^"]+)"', r.text)) == {
        "html", "md", "pdf",
    }
    assert "Форматы документации ФСТЭК" in r.text
    assert 'name="model"' not in r.text  # model choice removed: analyzer serves its own ai.model


def test_link_submission_rejects_foreign_host(client):
    c, _, _ = client
    r = c.post("/api/scans", data={"source_kind": "link", "repo_url": "https://evil.com/x"})
    assert r.status_code == 200
    assert "Ссылка недопустима" in r.text


def test_empty_submission_rejected(client):
    c, _, _ = client
    r = c.post("/api/scans", data={"source_kind": "link", "repo_url": ""})
    assert r.status_code == 200
    assert "Обязательное поле" in r.text


def test_files_mode_does_not_require_url_field(client):
    """Regression: the hidden URL field must not carry `required` when files
    mode is active — browsers block submission on hidden required inputs,
    which made file/zip uploads impossible without filling the URL."""
    c, _, _ = client
    r = c.post("/api/scans", data={"source_kind": "files"})
    assert r.status_code == 200
    assert "Не выбрано ни одного файла" in r.text

    m = re.search(r'<input id="field-repo_url"[^>]*>', r.text)
    assert m is not None, "repo_url input must stay in the form (hidden by JS)"
    assert "required" not in m.group(0)


def test_link_mode_keeps_required_url_field(client):
    c, _, _ = client
    r = c.post("/api/scans", data={"source_kind": "link", "repo_url": ""})
    m = re.search(r'<input id="field-repo_url"[^>]*>', r.text)
    assert m is not None
    assert "required" in m.group(0)


def test_zip_submission_with_traversal_shows_error(client):
    c, _, _ = client
    payload = make_zip_bytes({"../escape.py": b"x"})
    r = c.post(
        "/api/scans",
        data={"source_kind": "files", "repo_url": ""},
        files={"files": ("repo.zip", payload, "application/zip")},
    )
    assert r.status_code == 200
    assert "недопустимый путь" in r.text


def test_zip_submission_ok(client):
    c, _, data_dir = client
    payload = make_zip_bytes({"src/app.py": b"print(1)"})
    r = c.post(
        "/api/scans",
        data={"source_kind": "files", "repo_url": ""},
        files={"files": ("repo.zip", payload, "application/zip")},
        follow_redirects=False,
    )
    assert r.status_code == 303
    scan_id = r.headers["location"].rsplit("/", 1)[-1]
    assert (data_dir / "uploads" / scan_id / "repo" / "src" / "app.py").is_file()


def test_files_submission_lands_in_repo_dir(client):
    """Regression: plain multi-file uploads must land in uploads/{id}/repo/
    like zip uploads — the worker reads uploads/{id}/repo for both kinds and
    used to crash with FileNotFoundError on this layout."""
    c, _, data_dir = client
    r = c.post(
        "/api/scans",
        data={"source_kind": "files", "repo_url": ""},
        files=[
            ("files", ("src/app.py", b"print(1)", "text/x-python")),
            ("files", ("README.md", b"# demo", "text/markdown")),
        ],
        follow_redirects=False,
    )
    assert r.status_code == 303
    scan_id = r.headers["location"].rsplit("/", 1)[-1]
    assert (data_dir / "uploads" / scan_id / "repo" / "src" / "app.py").is_file()
    assert (data_dir / "uploads" / scan_id / "repo" / "README.md").is_file()
    assert (data_dir / "uploads" / scan_id / "scan.json").is_file()


def test_scan_page_shows_no_live_elapsed_while_running(client):
    """Fresh submission: stages pending, timings are not displayed."""
    c, _, _ = client
    r = c.post(
        "/api/scans",
        data={"source_kind": "link", "repo_url": "https://github.com/owner/repo"},
        follow_redirects=False,
    )
    scan_id = r.headers["location"].rsplit("/", 1)[-1]
    page = c.get(f"/scan/{scan_id}")
    assert page.status_code == 200
    assert "Прошло:" not in page.text  # timings are data-only since the rebase


def test_status_unknown_scan(client):
    c, _, _ = client
    assert c.get("/api/scans/not-a-uuid/status").json() == {"error": "not_found"}
    assert c.get("/api/scans/00000000-0000-0000-0000-000000000099/status").json() == {"error": "not_found"}


def test_scan_page_not_found(client):
    c, _, _ = client
    r = c.get("/scan/00000000-0000-0000-0000-000000000099")
    assert r.status_code == 404


def test_artifacts_served_with_contract_headers(client, demo_scan):
    c, _, _ = client
    listing = c.get(f"/api/scans/{demo_scan}/artifacts").json()
    # doc.md is filtered out: md is no longer a format of the doc document
    assert set(listing["artifacts"]) == {"report.html", "doc.html", "doc.pdf"}
    assert listing["summary"]["severities"]["critical"] == 1

    pdf = c.get(f"/api/scans/{demo_scan}/artifacts/doc.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert "attachment" in pdf.headers["content-disposition"]

    html = c.get(f"/api/scans/{demo_scan}/artifacts/report.html")
    assert html.status_code == 200
    assert html.headers["content-security-policy"] == "sandbox allow-scripts"


def test_unknown_artifact_rejected(client, demo_scan):
    c, _, _ = client
    assert c.get(f"/api/scans/{demo_scan}/artifacts/secret.txt").status_code == 404
    assert c.get(f"/api/scans/{demo_scan}/artifacts/..%2Freport.html").status_code in (404, 400)


def test_scan_page_shows_results_when_ready(client, demo_scan):
    c, _, _ = client
    r = c.get(f"/scan/{demo_scan}")
    assert r.status_code == 200
    assert "Документация ФСТЭК" in r.text
    assert "Документация ФСТЭК · PDF" in r.text
    assert "Документация ФСТЭК · MD" not in r.text  # md left the FSTEC doc formats
    assert "Отчёт аудита · MD" not in r.text  # demo fixture publishes report.html only
    assert 'id="donut"' not in r.text  # the only donut lives inside the embedded report
    assert "/artifacts/report.html" in r.text  # audit report embedded on the page
    assert "Анализ: 41.7 с" not in r.text  # timing block from summary.json is data-only
    assert "Прошло" not in r.text  # live elapsed only while stages run

    viewer = c.get(f"/scan/{demo_scan}/view/report.html")
    assert viewer.status_code == 200
    assert 'sandbox="allow-scripts"' in viewer.text
    assert f"/api/scans/{demo_scan}/artifacts/report.html" in viewer.text


def test_viewer_route_rejects_non_framed_artifact(client, demo_scan):
    c, _, _ = client
    assert c.get(f"/scan/{demo_scan}/view/report.pdf").status_code == 404
