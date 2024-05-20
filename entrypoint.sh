#! /bin/bash

set -e

cd competition_api && poetry run alembic upgrade head && cd -

poetry run uvicorn competition_api.main:app --host 0.0.0.0 --port 80
