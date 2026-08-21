SHELL := /bin/bash

ROOT := $(abspath $(CURDIR))
PACKAGE_NAME := dwlabbind
PYTHON ?= python3
BUILD_ARTIFACTS := dist
INSTALL_TARGET ?=

.PHONY: help build clean inspect install

help:
	@echo "Targets for $(PACKAGE_NAME):"
	@echo "  make build        Build wheel and sdist artifacts into $(BUILD_ARTIFACTS)"
	@echo "  make clean        Remove local build artifacts"
	@echo "  make inspect      List generated distribution files"
	@echo "  make install      Pip install into INSTALL_TARGET or the active environment"

build:
	$(PYTHON) -m build --no-isolation

clean:
	rm -rf .pybuild build dist *.egg-info src/*.egg-info tests/output

inspect:
	@ls -1 "$(BUILD_ARTIFACTS)"/$(PACKAGE_NAME)-* 2>/dev/null || echo "No distribution artifacts built yet."

install:
	$(PYTHON) -m pip install $(if $(INSTALL_TARGET),--target "$(INSTALL_TARGET)",.) .
