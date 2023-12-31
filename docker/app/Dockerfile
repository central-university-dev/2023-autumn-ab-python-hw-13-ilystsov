FROM python:3.11 AS builder

WORKDIR /opt/build

RUN pip install poetry

COPY pyproject.toml poetry.lock src ./

RUN poetry config virtualenvs.create false \
    && poetry install --without dev

FROM python:3.11-slim

WORKDIR /opt/app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY src /opt/app/src
COPY .env ./


CMD ["gunicorn", "-b", "0.0.0.0:8000", "src.app:app"]