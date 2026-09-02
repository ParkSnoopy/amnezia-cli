GO ?= go
DIST := $(CURDIR)/dist
LIBEXEC := $(DIST)/libexec/amn
BUILD_FLAGS := -trimpath -buildvcs=false

.PHONY: all amn xray wireguard-go amneziawg-go clean test

all: amn xray wireguard-go amneziawg-go

amn:
	mkdir -p $(DIST)
	CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -ldflags='-s -w' -o $(DIST)/amn ./cmd/amn

xray:
	mkdir -p $(LIBEXEC)
	cd thirdparty/xray-core && CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -ldflags='-s -w' -o $(LIBEXEC)/xray ./main

wireguard-go:
	mkdir -p $(LIBEXEC)
	cd thirdparty/wireguard-go && CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -ldflags='-s -w' -o $(LIBEXEC)/wireguard-go .

amneziawg-go:
	mkdir -p $(LIBEXEC)
	cd thirdparty/amneziawg-go && CGO_ENABLED=0 $(GO) build $(BUILD_FLAGS) -ldflags='-s -w' -o $(LIBEXEC)/amneziawg-go .

test:
	$(GO) test ./...
	$(GO) vet ./...

clean:
	rm -rf $(DIST)
