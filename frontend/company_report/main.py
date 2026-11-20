"""Internal service assembling editable forms from the FSTEC table configuration."""

import json
from io import BytesIO
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.shared import Cm, Pt
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field, field_validator

TEMPLATES = json.loads(
    (Path(__file__).resolve().parents[1] / "config/company_templates.json").read_text(encoding="utf-8")
)
MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
app = FastAPI()


class ReportRequest(BaseModel):
    inn: str = Field(pattern=r"^[0-9]{10}$")
    org: str = Field(min_length=1, max_length=300)
    sections: list[str] = Field(min_length=1, max_length=3)

    @field_validator("org")
    @classmethod
    def validate_org(cls, value):
        if not value.strip() or any(ord(char) < 32 or ord(char) in (0xfffe, 0xffff) for char in value):
            raise ValueError("Invalid organization name")
        return value.strip()


@app.post("/reports")
def generate_report(payload: ReportRequest):
    selected = set(payload.sections)
    if selected.difference(TEMPLATES):
        raise HTTPException(422, "Unknown section")
    doc = Document()
    page = doc.sections[0]
    page.orientation = WD_ORIENT.LANDSCAPE
    page.page_width, page.page_height = Cm(29.7), Cm(21)
    page.left_margin = page.right_margin = Cm(1.5)
    page.top_margin = page.bottom_margin = Cm(1.5)
    doc.styles["Normal"].font.size = Pt(10)
    for key, template in TEMPLATES.items():
        if key not in selected:
            continue
        for index, spec in enumerate(template["tables"]):
            if doc.paragraphs:
                doc.add_page_break()
            if index == 0:
                doc.add_heading(template["label"], 1)
            doc.add_paragraph(f"{payload.org} · ИНН {payload.inn}")
            if index == 0:
                doc.add_paragraph(template["instruction"])
            doc.add_paragraph(spec["title"])
            columns = spec["columns"]
            table = doc.add_table(rows=2 + spec["rows"], cols=len(columns))
            table.style = "Table Grid"
            weights = [max(1, min(len(label) / 18, 6)) for label in columns]
            table.autofit = False
            for col, weight in zip(table.columns, weights, strict=True):
                col.width = Cm(26.7 * weight / sum(weights))
                for cell in col.cells:
                    cell.width = col.width
            for i, label in enumerate(columns):
                table.cell(0, i).text = label
                table.cell(1, i).text = str(i + 1)
            if spec.get("signature"):
                doc.add_paragraph("________________________     ______________     ________________________")
                doc.add_paragraph("Должность уполномоченного лица                 Подпись                     Инициалы, фамилия")
    result = BytesIO()
    doc.save(result)
    return Response(result.getvalue(), media_type=MIME)
