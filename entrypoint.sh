#! /bin/bash

set -e

LOCAL_USER=${LOCAL_USER:-1000:1000}
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

MODE=${MODE:-api}

if [[ "${MODE}" = "worker" ]]; then
	until docker version >/dev/null 2>/dev/null; do
		echo "Waiting for Docker daemon to start"
		sleep 5
	done
	IMAGE_FILES=$(find "${AIXCC_CP_ROOT}" -type f -name "img-*.tar.gz")
	echo "Loading CP images from local files"
	for IMAGE_FILE in $IMAGE_FILES; do
		echo "Loading CP container: $IMAGE_FILE"
		docker load -i "$IMAGE_FILE"
	done
	$BASH -c "poetry run wait-for-redis"
	$BASH -c "poetry run arq competition_api.tasks.Worker"
elif [[ "${MODE}" = "monitor" ]]; then
	while true; do
		$BASH -c "poetry run arq --check competition_api.tasks.Worker" || echo "Initial health status pending"
		sleep $((AIXCC_WORKER_HEALTH_CHECK_INTERVAL * 3 / 2))
	done
elif [[ "${MODE}" = "background" ]]; then
	$BASH -c "poetry run background"
else
	$BASH -c "cd competition_api && poetry run alembic upgrade head && cd -"
	$BASH -c "poetry run prestart"
	$BASH -c "poetry run uvicorn competition_api.main:app --host 0.0.0.0 --port ${AIXCC_PORT:-8080} --workers ${WEB_CONCURRENCY:-4}"
fi
