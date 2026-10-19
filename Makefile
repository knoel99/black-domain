# BDOS -- Black Domain OS
#
# Convenience entrypoints for developing, hardening, and packaging BDOS.
# `make help` lists every target. Python steps use python3 (the interpreter that
# carries cryptography + cffi); OS steps shell out to os/install.sh.

PYTHON  ?= python3
PIP     ?= $(PYTHON) -m pip
PYSRC   := $(shell find bdos -name '*.py')

.DEFAULT_GOAL := help

.PHONY: help test lint install clean image

help: ## Show this help
	@echo "BDOS make targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

test: ## Run the full test suite
	$(PYTHON) -m pytest -q

lint: ## Byte-compile every bdos module (fast syntax/import-shape check)
	$(PYTHON) -m py_compile $(PYSRC)
	@echo "lint: py_compile clean ($(words $(PYSRC)) files)"

install: ## Install the OS overlay onto this host (runs os/install.sh; needs root)
	bash os/install.sh

clean: ## Remove build artifacts and Python caches
	rm -rf build dist *.egg-info bdos.egg-info .pytest_cache
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
	@echo "clean: done"

image: ## Build a bootable BDOS image (stub -- see os/profile/README.md)
	@echo "BDOS image build is documented in os/profile/README.md"
	@echo "Outline:"
	@echo "  1. debootstrap/mkosi a minimal base into ./rootfs"
	@echo "  2. run 'BDOS_APPLY=0 ./os/install.sh' inside the rootfs"
	@echo "  3. enable bdosd.service + bdos-sentinel.service, add kernel+bootloader"
	@echo "  4. seal enclaves on first boot: 'bdosctl seal crown-jewels'"
	@echo "(stub target: wire this to your image toolchain of choice)"
