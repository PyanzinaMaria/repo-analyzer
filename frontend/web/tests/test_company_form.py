import sys
from io import BytesIO
from pathlib import Path

from docx import Document
from fastapi.testclient import TestClient


def test_company_form_and_generation(client, demo_scan, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]))
    from company_report.main import TEMPLATES, app

    browser, _, _ = client
    url = f"/scan/{demo_scan}/company"
    assert "Подготовить шаблон" in browser.get(f"/scan/{demo_scan}").text
    page = browser.get(url)
    assert page.status_code == 200
    assert page.text.count('name="sections"') == 3
    assert 'name="inn"' in page.text
    assert 'name="org"' in page.text
    payload = {"inn": "7700000000", "org": "ООО Пример", "sections": ["equipment", "docs"]}
    with TestClient(app) as report_service:
        result = report_service.post("/reports", json=payload)
        assert result.status_code == 200
        doc = Document(BytesIO(result.content))
        assert len(doc.tables) == 2
        assert "ООО Пример · ИНН 7700000000" in [p.text for p in doc.paragraphs]
        for table, key in zip(doc.tables, payload["sections"], strict=True):
            assert [cell.text for cell in table.rows[0].cells] == TEMPLATES[key]["tables"][0]["columns"]
        assert report_service.post("/reports", json={**payload, "sections": []}).status_code == 422
        software = report_service.post("/reports", json={**payload, "sections": ["software"]})
        assert len(Document(BytesIO(software.content)).tables) == 4
    sys.modules.pop("company_report.main", None)
