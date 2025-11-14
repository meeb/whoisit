test:
	uv run python -m pytest -v


build:
	uv build


tld-endpoints:
	uv run tools/list_public_tlds_with_rdap_endpoints.py


check:
	uvx ruff check


format:
	uvx ruff format
