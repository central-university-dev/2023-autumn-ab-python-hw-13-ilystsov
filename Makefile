CODE_FOLDERS := src
TEST_FOLDERS := tests

.PHONY: test format lint run

test:
	poetry run pytest $(TEST_FOLDERS) --cov=$(CODE_FOLDERS) --cov-fail-under=95

format:
	poetry run black --line-length 79 $(CODE_FOLDERS) $(TEST_FOLDERS)

lint:
	poetry run flake8 $(CODE_FOLDERS) $(TEST_FOLDERS)

run:
	poetry run gunicorn --reload app:app