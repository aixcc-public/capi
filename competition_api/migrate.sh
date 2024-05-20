#! /bin/bash

MESSAGE=${1}

export CAPI_DATABASE_NAME="capi"
export CAPI_DATABASE_USERNAME="capi"
export CAPI_DATABASE_PASSWORD="capisecret" # gitleaks:allow

CONTAINER=capi-migrations

function kill_container() {
	# if the container is there, stop and remove it
	docker rm -f ${CONTAINER}
}
# if this script exits, shut down the container
trap kill_container EXIT

# start up the postgres container
kill_container
docker run \
	--name ${CONTAINER} \
	-e POSTGRES_PASSWORD=${CAPI_DATABASE_PASSWORD} \
	-e POSTGRES_USER=${CAPI_DATABASE_USERNAME} \
	-e POSTGRES_DB=${CAPI_DATABASE_NAME} \
	-p 5432 \
	-d \
	postgres:16

PORT=$(docker port capi-migrations 5432 | head -1 | sed 's/.*://g')
export CAPI_DATABASE_HOST="127.0.0.1"
export CAPI_DATABASE_PORT=${PORT}

sleep 2

poetry run alembic upgrade head
poetry run alembic revision --autogenerate -m "${MESSAGE}"
