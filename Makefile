MODULES=challenge_api

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
