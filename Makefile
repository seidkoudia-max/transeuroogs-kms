GO ?= go
PYTHON ?= python3
APP_PYTHON ?= python3

.PHONY: check fmt test vet build pki demo relay-demo segmented-demo metadata-demo sdn-demo compose-demo operational-demo app-test

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

segmented-demo: build
	$(GO) build -trimpath -o .local/bin/eagle-emulator ./src/cmd/eagle-emulator
	$(GO) build -trimpath -o .local/bin/test-pki ./src/cmd/test-pki
	$(PYTHON) emulator/eagle1-kms/demo.py --binary .local/bin/kms --emulator .local/bin/eagle-emulator --pki-binary .local/bin/test-pki

compose-demo:
	docker compose run --build --rm pki
	docker compose up --build --abort-on-container-exit --exit-code-from sae kms sae

metadata-demo: build
	$(GO) build -trimpath -o .local/bin/eagle-emulator ./src/cmd/eagle-emulator
	$(GO) build -trimpath -o .local/bin/test-pki ./src/cmd/test-pki
	$(GO) build -trimpath -o .local/bin/kms-metadata ./src/cmd/kms-metadata
	$(PYTHON) emulator/eagle1-kms/demo.py --binary .local/bin/kms --emulator .local/bin/eagle-emulator --pki-binary .local/bin/test-pki --metadata-binary .local/bin/kms-metadata

sdn-demo: build
	$(GO) build -trimpath -o .local/bin/test-pki ./src/cmd/test-pki
	$(GO) build -trimpath -o .local/bin/kms-metadata ./src/cmd/kms-metadata
	$(PYTHON) emulator/sdn/demo.py --binary .local/bin/kms --pki-binary .local/bin/test-pki --metadata-binary .local/bin/kms-metadata --node-output .local/sdn-node.json

app-test:
	$(APP_PYTHON) -m unittest discover -s src/application -p 'test_*.py'

operational-demo:
	$(APP_PYTHON) tests/operational_acceptance.py --go $(GO)

.PHONY: federation-demo
federation-demo: build
	$(GO) build -trimpath -o .local/bin/eagle-emulator ./src/cmd/eagle-emulator
	$(GO) build -trimpath -o .local/bin/test-pki ./src/cmd/test-pki
	$(PYTHON) emulator/eagle1-kms/demo.py --binary .local/bin/kms --emulator .local/bin/eagle-emulator --pki-binary .local/bin/test-pki --federation

.PHONY: sdn-services-demo
sdn-services-demo: build
	$(GO) build -trimpath -o .local/bin/test-pki ./src/cmd/test-pki
	$(GO) build -trimpath -o .local/bin/kms-metadata ./src/cmd/kms-metadata
	$(PYTHON) -m unittest discover -s tests -p test_sdn_services.py
	$(PYTHON) emulator/sdn/services.py --binary .local/bin/kms --pki-binary .local/bin/test-pki --metadata-binary .local/bin/kms-metadata --node-output .local/sdn-services-node.json

.PHONY: services-deployment-test services-bundle
services-deployment-test:
	$(PYTHON) -m unittest discover -s tests -p test_services_deployment.py
	$(PYTHON) -m py_compile deploy/services/*.py src/sdn/teraflow/controller.py

services-bundle: services-deployment-test
	mkdir -p .local/services-bin
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -o .local/services-bin/ ./src/cmd/kms ./src/cmd/kms-metadata ./src/cmd/test-pki
	$(PYTHON) deploy/services/package.py .local/services-release.tar.gz
