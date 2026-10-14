.PHONY: install format lint typecheck security contracts test integration check helm terraform audit-deps image run clean

CHART := deployments/helm/agent-action-provenance

install:
	uv sync

format:
	uv run black src tests
	uv run ruff check src tests --fix

lint:
	uv run ruff check src tests
	uv run black --check src tests

typecheck:
	uv run mypy

security:
	uv run python -m bandit -q -r src -c pyproject.toml

contracts:
	uv run python -m agent_action_provenance.contracts --check

test:
	uv run pytest

integration:
	uv run pytest tests/integration -m integration --no-cov

check: lint typecheck security contracts test

helm:
	helm lint $(CHART) -f $(CHART)/ci/test-values.yaml
	helm template provenance $(CHART) -f $(CHART)/ci/test-values.yaml > /dev/null
	! helm template provenance $(CHART) > /dev/null 2>&1

terraform:
	terraform fmt -recursive -check deployments/terraform
	for c in aws azure gcp; do terraform -chdir=deployments/terraform/$$c init -backend=false -input=false && terraform -chdir=deployments/terraform/$$c validate; done

audit-deps:
	# agentic-core is a pinned git dependency (audited in its own repository);
	# everything from PyPI is audited here with hashes.
	uv export --frozen --no-dev --no-emit-project | grep -v '^agentic-core @' > requirements.audit.txt
	uvx pip-audit -r requirements.audit.txt --disable-pip
	rm -f requirements.audit.txt

image:
	docker build -t agent-action-provenance:dev .

run:
	docker compose up --build

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
