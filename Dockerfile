FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e .
ENTRYPOINT ["kairos"]
CMD ["scan-dir", "data/sample_emails", "--config", "configs/policies.json"]
