PYTHON ?= python
PACKAGE = dwlabbind

.PHONY: help init show add-zone remove-zone serve-api

help:
	@echo "Targets:"
	@echo "  init        Initialize a config"
	@echo "  show        Show current config"
	@echo "  add-zone    Add a zone"
	@echo "  remove-zone Remove a zone"
	@echo "  serve-api   Run REST API server"

init:
	$(PYTHON) -m $(PACKAGE).runner init --name ns1 --ip 192.0.2.10 --role master --config ./bind.xml

show:
	$(PYTHON) -m $(PACKAGE).runner show --config ./bind.xml

add-zone:
	$(PYTHON) -m $(PACKAGE).runner add-zone --config ./bind.xml --name example.com --type master --file db.example.com

remove-zone:
	$(PYTHON) -m $(PACKAGE).runner remove-zone --config ./bind.xml --name example.com

serve-api:
	$(PYTHON) -m $(PACKAGE).runner serve-api --config ./bind.xml --host 127.0.0.1 --port 8080
