# reconkg developer entry points.
#
# `check` is what CI and a human should both run: the unit suite plus the
# mutation harness. Mutation is separated from `test` because it takes
# minutes, not seconds, and a target nobody runs is worse than no target.

PYTHON ?= python3
PIP_FLAGS ?=
# Modules the mutation harness covers. `make mutation MUT_MODULES=vulnref`
# narrows it when iterating.
MUT_MODULES ?= vulnref models auth catalog sources ratelimit importers

.DEFAULT_GOAL := help
.PHONY: help install test mutation lint check clean

help:
	@echo "install   editable install with dev extras"
	@echo "test      full pytest suite"
	@echo "mutation  audit/mutation.py over \$$(MUT_MODULES)"
	@echo "lint      byte-compile + packaging metadata sanity"
	@echo "check     test + mutation"
	@echo "clean     remove caches and build artefacts"

install:
	$(PYTHON) -m pip install $(PIP_FLAGS) -e ".[dev]"

test:
	$(PYTHON) -m pytest -q

mutation:
	$(PYTHON) audit/mutation.py $(MUT_MODULES)

# No linter is declared as a dependency, and adding one just to have a `lint`
# target would be the same undeclared-dependency mistake this cycle exists to
# fix. So lint checks what is checkable with the stdlib: every file compiles,
# and the packaging metadata parses and resolves.
lint:
	$(PYTHON) -m compileall -q reconkg tests audit
	$(PYTHON) -c "import sys; \
	    tomllib = __import__('tomllib') if sys.version_info >= (3, 11) \
	    else __import__('tomli'); \
	    d = tomllib.load(open('pyproject.toml', 'rb')); \
	    print('pyproject ok:', d['project']['name'], d['project']['version'])"

check: test mutation

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
