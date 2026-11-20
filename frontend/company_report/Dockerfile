FROM python:3.12-slim
WORKDIR /srv
COPY web/requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir -r /tmp/requirements.lock
COPY company_report /srv/company_report
COPY config/company_templates.json /srv/config/company_templates.json
CMD ["python", "-m", "uvicorn", "company_report.main:app", "--host", "0.0.0.0", "--port", "8000"]
