GO        ?= go
BIN       := bin
CMDS      := attestctl attestd
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS   := -s -w -X main.version=$(VERSION)
# Static, CGO-free Linux binaries are the release target.
LINUX_ARCHES := amd64 arm64

.PHONY: all build test race e2e lint vet fmt-check vuln linux check clean swtpm-up swtpm-down test-tpm \
	saturation saturation-smoke \
	generate generate-check proto-lint tools

all: check build

build:
	@mkdir -p $(BIN)
	$(foreach c,$(CMDS),CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/$(c) ./cmd/$(c) &&) true

test:
	$(GO) test -count=1 ./...

race:
	$(GO) test -race -count=1 ./...

e2e:
	$(GO) test -tags e2e -count=1 -v ./e2e/...

# Load and fault-injection tests. SCALE multiplies the work; the smoke run
# keeps CI fast and adds the race detector.
SCALE ?= 10
saturation:
	ATTEST_SATURATION_SCALE=$(SCALE) $(GO) test -tags saturation -count=1 -timeout 30m -run Saturation -v ./internal/api/

saturation-smoke:
	ATTEST_SATURATION_SCALE=1 $(GO) test -race -tags saturation -count=1 -timeout 10m -run Saturation ./internal/api/

vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./e2e/...
	$(GO) vet -tags swtpm ./...
	$(GO) vet -tags saturation ./internal/api/

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

linux:
	@mkdir -p $(BIN)
	$(foreach a,$(LINUX_ARCHES),$(foreach c,$(CMDS),CGO_ENABLED=0 GOOS=linux GOARCH=$(a) $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/$(c)-linux-$(a) ./cmd/$(c) &&)) true

check: fmt-check vet lint race e2e

clean:
	rm -rf $(BIN)

# --- API code generation ------------------------------------------------------
# Generator versions are pinned and installed into .tools so generated code
# is reproducible; it is committed and CI rejects stale output.
TOOLS                  := $(CURDIR)/.tools
BUF_VERSION            := v1.74.0
PROTOC_GEN_GO_VERSION  := v1.34.2
PROTOC_GEN_GRPC_VERSION := v1.5.1
BUF := $(TOOLS)/buf

$(TOOLS)/.v-$(BUF_VERSION)-$(PROTOC_GEN_GO_VERSION)-$(PROTOC_GEN_GRPC_VERSION):
	@rm -rf $(TOOLS) && mkdir -p $(TOOLS)
	GOBIN=$(TOOLS) $(GO) install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	GOBIN=$(TOOLS) $(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(TOOLS) $(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GRPC_VERSION)
	@touch $@

tools: $(TOOLS)/.v-$(BUF_VERSION)-$(PROTOC_GEN_GO_VERSION)-$(PROTOC_GEN_GRPC_VERSION)

proto-lint: tools
	$(BUF) lint

generate: tools proto-lint
	@rm -rf api/gen
	PATH=$(TOOLS):$$PATH $(BUF) generate

generate-check: generate
	@git diff --exit-code -- api/gen && \
	  test -z "$$(git status --porcelain -- api/gen)" || \
	  { echo "generated API code is stale: run make generate"; exit 1; }

# --- Development software TPM (Docker) ---------------------------------------
SWTPM_IMAGE ?= attest-swtpm
SWTPM_NAME  ?= attest-swtpm
SWTPM_DIR   := $(CURDIR)/.swtpm
export ATTEST_SWTPM_ADDR ?= 127.0.0.1:2321
export ATTEST_SWTPM_CTRL ?= 127.0.0.1:2322
export ATTEST_SWTPM_DIR  ?= $(SWTPM_DIR)

swtpm-up: swtpm-down
	docker build -q -t $(SWTPM_IMAGE) deploy/swtpm >/dev/null
	@rm -rf $(SWTPM_DIR) && mkdir -p $(SWTPM_DIR)
	docker run -d --rm --name $(SWTPM_NAME) \
	  -p 127.0.0.1:2321:2321 -p 127.0.0.1:2322:2322 \
	  -v $(SWTPM_DIR):/out $(SWTPM_IMAGE) >/dev/null
	@for i in $$(seq 1 60); do [ -f $(SWTPM_DIR)/ready ] && exit 0; sleep 0.5; done; \
	  docker logs $(SWTPM_NAME); echo "swtpm did not become ready"; exit 1

swtpm-down:
	-@docker rm -f $(SWTPM_NAME) >/dev/null 2>&1 || true

# Requires `make swtpm-up`. Tests share one TPM, so packages run serially.
test-tpm:
	$(GO) test -tags swtpm -p 1 -count=1 ./...
