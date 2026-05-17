.PHONY: test lint run-api run-dashboard scan scan-sbom scan-diff docker-build docker-up clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

test: ## Run all tests
	python -m pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage report
	python -m pytest tests/ -v --tb=short --cov=. --cov-report=term-missing --cov-config=pyproject.toml

lint: ## Lint with ruff
	python -m ruff check .

format: ## Auto-format with ruff
	python -m ruff format .

scan: ## Run a scan with sample inventory (no LLM)
	python main.py -i sample_inventory.csv --no-llm --sarif

scan-sbom: ## Run a scan with sample SBOM (no LLM)
	python main.py -i sample_sbom_cyclonedx.json --no-llm --sarif

scan-diff: ## Run scan and diff against latest previous report
	@latest=$$(ls -t output/*_report.json 2>/dev/null | head -1); \
	if [ -n "$$latest" ]; then \
		python main.py -i sample_inventory.csv --no-llm --diff "$$latest"; \
	else \
		echo "No previous report found. Run 'make scan' first."; \
	fi

run-api: ## Start FastAPI server on port 8000
	uvicorn api:app --reload --host 0.0.0.0 --port 8000

run-dashboard: ## Start Streamlit dashboard on port 8501
	streamlit run dashboard.py --server.port 8501

docker-build: ## Build Docker image
	docker build -t ics-scanner .

docker-up: ## Run full stack with docker-compose
	docker compose up --build

clean: ## Remove caches and output files
	rm -rf __pycache__ .pytest_cache .ruff_cache .cache/kev_catalog.json output/*
	find . -name '*.pyc' -delete

install: ## Install all dependencies
	pip install -r requirements.txt

install-dev: ## Install with dev dependencies
	pip install -r requirements.txt && pip install ruff coverage
