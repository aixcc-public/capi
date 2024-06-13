MODULES=competition_api tests
ROOT_DIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

# variables that control the volumes
HOST_CAPI_LOGS = $(ROOT_DIR)/capi_logs
export AUDIT_LOG = $(HOST_CAPI_LOGS)/audit.log

# variables the control the CP repos
HOST_CP_ROOT_DIR = $(ROOT_DIR)/cp_root

VOLUMES = $(HOST_CAPI_LOGS) $(HOST_CP_ROOT_DIR)

.PHONY: format sec lint build run test up down demo

format:
	poetry run isort $(MODULES)
	poetry run black $(MODULES)

sec:
	poetry run bandit $(MODULES)
	poetry run safety check $(MODULES)

lint:
	RC=0; \
	poetry run pylint $(MODULES) || RC=1; \
	poetry run black --check $(MODULES) || RC=1; \
	poetry run isort --check $(MODULES) || RC=1; \
	poetry run mypy $(MODULES) || RC=1; \
	exit $$RC

local-volumes:
	mkdir -p $(VOLUMES)

build:
	@docker build . -t capi

run: build
	docker run -it capi

test:
	poetry run pytest --cov=competition_api --cov-report term-missing:skip-covered ${TESTS}

compose-build:
	docker-compose build

up: local-volumes mock-cp compose-build
	WEB_CONCURRENCY=4 docker-compose up

down:
	docker-compose down

jenkins-cp: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone git@github.com:aixcc-sc/challenge-002-jenkins-cp.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare

mock-cp: local-volumes
	rm -rf $(HOST_CP_ROOT_DIR)/$@
	git clone git@github.com:aixcc-sc/mock-cp.git $(HOST_CP_ROOT_DIR)/$@
	cd $(HOST_CP_ROOT_DIR)/$@ && make cpsrc-prepare

clean-volumes:
	rm -rf $(VOLUMES)

clean:
	docker-compose down -v

e2e: clean clean-volumes local-volumes mock-cp compose-build
	:>$(AUDIT_LOG)
	WEB_CONCURRENCY=4 docker-compose up -d
	cd e2e && ./run.sh; docker-compose down
	cat $(AUDIT_LOG)
