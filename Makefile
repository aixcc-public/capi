MODULES=competition_api tests

.PHONY: format sec lint build run test up down demo

format:
	poetry run isort $(MODULES)
	poetry run black $(MODULES)

sec:
	poetry run bandit $(MODULES)
	poetry run safety check $(MODULES)

lint:
	poetry run pylint $(MODULES)
	poetry run black --check $(MODULES)
	poetry run isort --check $(MODULES)
	poetry run mypy $(MODULES)

build:
	@docker build . -t capi

run: build
	docker run -it capi

test:
	poetry run pytest ${TESTS}

up:
	docker-compose build && WEB_CONCURRENCY=4 docker-compose up

down:
	docker-compose down

clean:
	docker-compose rm -v

demo:
	cd demo && ./run.sh
