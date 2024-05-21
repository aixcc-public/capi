#! /bin/bash

CAPI_PORT=${CAPI_PORT:-8080}

set -e

cd competition_api && poetry run alembic upgrade head && cd -

poetry run uvicorn competition_api.main:app --host 0.0.0.0 --port "${CAPI_PORT}"
