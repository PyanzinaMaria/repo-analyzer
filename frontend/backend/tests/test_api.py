"""API and page smoke tests over the full submission/serve flow."""

from __future__ import annotations

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
    assert set(listing["artifacts"]) == {"report.html", "doc.html", "report.pdf", "doc.pdf"}
    assert listing["summary"]["severities"]["critical"] == 1

    pdf = c.get(f"/api/scans/{demo_scan}/artifacts/report.pdf")
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
    assert "Документация ФСТЭК (смотреть)" in r.text
    assert "Отчёт аудита (PDF)" in r.text
    assert 'data-option' in r.text  # donut option embedded

    viewer = c.get(f"/scan/{demo_scan}/view/report.html")
    assert viewer.status_code == 200
    assert 'sandbox="allow-scripts"' in viewer.text
    assert f"/api/scans/{demo_scan}/artifacts/report.html" in viewer.text


def test_viewer_route_rejects_non_framed_artifact(client, demo_scan):
    c, _, _ = client
    assert c.get(f"/scan/{demo_scan}/view/report.pdf").status_code == 404
