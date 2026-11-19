.PHONY: test lint demo clean

test:
	pytest -q

lint:
	ruff check .

demo:
	agentbox demo

clean:
	rm -rf runs/ workspace/ .pytest_cache/ __pycache__/ .ruff_cache/
