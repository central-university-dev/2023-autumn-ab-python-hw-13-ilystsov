FROM python:3.11

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /opt/app

RUN pip install poetry

COPY pyproject.toml poetry.lock Makefile ./
COPY src ./src
COPY tests ./tests
COPY .env .env_template ./
COPY .coveragerc ./.coveragerc

RUN poetry config virtualenvs.create false \
    && poetry install

CMD ["gunicorn", "-b", "0.0.0.0:8000", "--reload", "src.app:app"]