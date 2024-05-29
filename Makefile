MODULES=competition_api tests

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

tempdirs:
	mkdir -p capi-logs

build:
	@docker build . -t capi

run: build
	docker run -it capi

test:
	poetry run pytest --cov=competition_api --cov-report term-missing:skip-covered ${TESTS}

compose-build:
	docker-compose build

up: tempdirs compose-build
	WEB_CONCURRENCY=4 docker-compose up

down:
	docker-compose down

clean:
	docker-compose down -v

e2e: tempdirs compose-build
	:>capi-logs/audit.log
	WEB_CONCURRENCY=4 docker-compose up -d
	cd e2e && ./run.sh; docker-compose down
	cat capi-logs/audit.log
