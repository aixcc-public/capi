#! /bin/bash

set -e

LOCAL_USER=${LOCAL_USER:-1000:1000}
WORKER_TIMEOUT_SECONDS=180
BASH="bash"

if [[ "${LOCAL_USER}" != "0:0" ]]; then
	# extract user and group from the variable
	LOCAL_USER_ID=${LOCAL_USER%:*}
	LOCAL_USER_GID=${LOCAL_USER#*:}

	mkdir -p /home/appuser
	groupadd -o -g "${LOCAL_USER_GID}" appuser 2>/dev/null
	useradd -o -m -g "${LOCAL_USER_GID}" -u "${LOCAL_USER_ID}" -d /home/appuser appuser 2>/dev/null

	chown -R appuser:appuser /home/appuser /var/log/capi

	export HOME=/home/appuser
	BASH="gosu appuser bash"
fi

$BASH -c "cd competition_api && poetry run alembic upgrade head && cd -"
$BASH -c "poetry run prestart"
$BASH -c "poetry run gunicorn -k uvicorn.workers.UvicornWorker competition_api.main:app --bind 0.0.0.0:${AIXCC_PORT:-8080} --timeout $WORKER_TIMEOUT_SECONDS"
