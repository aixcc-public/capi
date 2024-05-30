#! /bin/bash

AIXCC_PORT=${AIXCC_PORT:-8080}

set -e

cd competition_api && poetry run alembic upgrade head && cd -

poetry run uvicorn competition_api.main:app --host 0.0.0.0 --port "${AIXCC_PORT}"
