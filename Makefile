GO        ?= go
BIN       := bin
CMDS      := attestctl
LDFLAGS   := -s -w
# Static, CGO-free Linux binaries are the release target.
LINUX_ARCHES := amd64 arm64

.PHONY: all build test race e2e lint vet fmt-check vuln linux check clean

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

vet:
	$(GO) vet ./...
	$(GO) vet -tags e2e ./e2e/...

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
