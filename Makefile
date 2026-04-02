BINARY   := cc-permission-handler
BUILDDIR := build
MAIN_PKG := ./cmd/$(BINARY)

.PHONY: build clean test install proto

build: $(BUILDDIR)/$(BINARY)

$(BUILDDIR)/$(BINARY): go.mod go.sum $(wildcard **/*.go)
	go build -o $@ $(MAIN_PKG)

clean:
	rm -rf $(BUILDDIR)

test:
	go test ./...

install:
	go install $(MAIN_PKG)

proto:
	buf generate
