GO ?= go
PYTHON ?= python3

.PHONY: check fmt test vet build pki demo relay-demo compose-demo

check:
	$(PYTHON) tests/check_format.py $(GO)
	$(GO) vet ./...
	$(GO) test -race ./...
	$(GO) build ./...

fmt:
	$(GO) fmt ./...

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	mkdir -p .local/bin
	$(GO) build -trimpath -o .local/bin/kms ./src/cmd/kms

pki:
	$(GO) run ./src/cmd/test-pki --out .local/pki

demo: build pki
	$(PYTHON) emulator/sae/demo.py --binary .local/bin/kms --pki .local/pki --count 1000

relay-demo: build pki
	$(PYTHON) emulator/network/demo.py --binary .local/bin/kms --pki .local/pki

compose-demo:
	docker compose run --build --rm pki
	docker compose up --build --abort-on-container-exit --exit-code-from sae kms sae
