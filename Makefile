# mactelnet-proxy — Makefile
#
# Targets:
#   build       — static Go binary in ./bin/
#   test        — `go test ./...`
#   vulncheck   — `govulncheck` against the official Go vuln DB
#   docker      — Docker build for $(DOCKER_ARCH) (default: amd64)
#   docker-all  — build amd64, arm64, and armhf images
#   deb         — Debian .deb for $(DEB_ARCH) (default: amd64) → dist/
#   deb-all     — build amd64, arm64, and armhf .debs
#   upstream    — clone haakonnessjoen/MAC-Telnet into _upstream/ for porting reference
#   clean       — remove ./bin/ and ./dist/

# Locate go: prefer one on PATH, otherwise fall back to the highest
# /usr/lib/go-*/bin/go (Debian/Ubuntu golang-* package layout). Override
# with `make GO=/path/to/go` for any other location.
GO            ?= $(or $(shell command -v go 2>/dev/null),$(lastword $(sort $(wildcard /usr/lib/go-*/bin/go))))
GOFLAGS       ?= -trimpath
# Version stamp. `git describe` prints the nearest tag plus the commit
# count and short SHA (e.g. v0.2.0-3-g7a2b1c4), with -dirty when the
# working tree has uncommitted changes. Falls back to "dev" when the
# repo has no tags yet or this isn't a git checkout (tarball builds).
# Override at the command line for a one-off: `make build VERSION=1.0.0`.
VERSION       ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS       ?= -s -w -buildid= -X main.version=$(VERSION)
BIN_DIR       ?= bin
BIN_NAME      ?= mactelnet-proxy
# Default GOOS/GOARCH to whatever the local toolchain reports; override
# either to cross-compile, e.g. `make build GOARCH=arm64`. The output
# binary is suffixed with -<os>-<arch> so multi-arch builds don't
# overwrite each other in bin/ — `bin/mactelnet-proxy-linux-amd64`,
# `bin/mactelnet-proxy-linux-arm64`, etc.
GOOS          ?= $(shell $(GO) env GOOS)
GOARCH        ?= $(shell $(GO) env GOARCH)
BIN_OUT       ?= $(BIN_NAME)-$(GOOS)-$(GOARCH)
# Docker target architecture. One of: amd64, arm64, armhf. Each maps
# to deploy/docker/Dockerfile.<arch>. The image tag is suffixed so
# `make docker-all` produces three independently-runnable images.
#
# DOCKER_ARCH is the short name used in the Dockerfile suffix and tag;
# DOCKER_PLATFORM is the full buildx OCI platform string. The mapping
# lives in DOCKER_PLATFORM_<arch>; armhf → linux/arm/v7 because hard-
# float armhf is the v7 ABI in OCI manifest terms.
DOCKER_ARCH   ?= amd64
DOCKER_PLATFORM_amd64 := linux/amd64
DOCKER_PLATFORM_arm64 := linux/arm64
DOCKER_PLATFORM_armhf := linux/arm/v7
DOCKER_PLATFORM        = $(DOCKER_PLATFORM_$(DOCKER_ARCH))
DOCKER_IMG    ?= $(BIN_NAME)

# Debian package architecture. One of: amd64, arm64, armhf. Each maps
# to a Go GOARCH (+ GOARM for armhf=arm/v7) for the cross-compile, and
# to the resulting .deb's `Architecture:` field. dpkg-deb is the only
# external tool needed; no debhelper / dh_make.
DEB_ARCH      ?= amd64
DEB_GOARCH_amd64 := amd64
DEB_GOARCH_arm64 := arm64
DEB_GOARCH_armhf := arm
DEB_GOARM_amd64  :=
DEB_GOARM_arm64  :=
DEB_GOARM_armhf  := 7
DEB_GOARCH        = $(DEB_GOARCH_$(DEB_ARCH))
DEB_GOARM         = $(DEB_GOARM_$(DEB_ARCH))
# DEB_VERSION comes from the Debian changelog so package and binary
# filenames match what dpkg-buildpackage actually produces. The git
# tag and the changelog Version are kept in sync manually — bump both
# when cutting a release. dpkg-parsechangelog is part of dpkg-dev,
# which is already a hard dep for `dpkg-buildpackage` itself.
DEB_VERSION   = $(shell dpkg-parsechangelog -SVersion -ldebian/changelog 2>/dev/null)
DEB_PKG       = $(BIN_NAME)_$(DEB_VERSION)_$(DEB_ARCH).deb
DIST_DIR      ?= dist

.PHONY: build test vulncheck docker docker-amd64 docker-arm64 docker-armhf docker-all deb deb-amd64 deb-arm64 deb-armhf deb-all upstream clean

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -C src $(GOFLAGS) -ldflags '$(LDFLAGS)' -o ../$(BIN_DIR)/$(BIN_OUT) ./cmd/mactelnet-proxy
	@echo "built $(BIN_DIR)/$(BIN_OUT)"

test:
	$(GO) test -C src ./...

vulncheck:
	$(GO) run -C src golang.org/x/vuln/cmd/govulncheck@latest ./...

docker:
	@if [ -z "$(DOCKER_PLATFORM)" ]; then echo "unknown DOCKER_ARCH=$(DOCKER_ARCH); use amd64|arm64|armhf"; exit 2; fi
	docker buildx build --network host --platform=$(DOCKER_PLATFORM) --load --build-arg VERSION=$(VERSION) -t $(DOCKER_IMG):dev-$(DOCKER_ARCH) -f deploy/docker/Dockerfile.$(DOCKER_ARCH) .

docker-amd64:
	$(MAKE) docker DOCKER_ARCH=amd64
docker-arm64:
	$(MAKE) docker DOCKER_ARCH=arm64
docker-armhf:
	$(MAKE) docker DOCKER_ARCH=armhf

docker-all: docker-amd64 docker-arm64 docker-armhf

# ── Debian package builds ────────────────────────────────────────────
#
# Thin wrappers around `dpkg-buildpackage`. The Debian source-package
# layout lives under ./debian/ at the project root; `dpkg-buildpackage`
# runs debian/rules which builds the Go binary, stages it under
# debian/mactelnet-proxy/, and `dpkg-deb`-ies the result up one
# directory (per dpkg convention). We move the artifacts into
# $(DIST_DIR) afterwards so the project root stays tidy.
#
# Cross-arch builds work because Go cross-compiles natively;
# debian/rules sets GOARCH/GOARM from $(DEB_HOST_ARCH).
deb:
	@command -v dpkg-buildpackage >/dev/null || { echo "dpkg-buildpackage not found; apt install dpkg-dev"; exit 2; }
	@if [ -z "$(DEB_GOARCH)" ]; then echo "unknown DEB_ARCH=$(DEB_ARCH); use amd64|arm64|armhf"; exit 2; fi
	dpkg-buildpackage -b -uc -us -tc --host-arch=$(DEB_ARCH) -d
	@mkdir -p $(DIST_DIR)
	@mv ../$(BIN_NAME)_*_$(DEB_ARCH).deb       $(DIST_DIR)/ 2>/dev/null || true
	@mv ../$(BIN_NAME)_*_$(DEB_ARCH).buildinfo $(DIST_DIR)/ 2>/dev/null || true
	@mv ../$(BIN_NAME)_*_$(DEB_ARCH).changes   $(DIST_DIR)/ 2>/dev/null || true
	@echo "built $(DIST_DIR)/$(DEB_PKG)"

deb-amd64:
	$(MAKE) deb DEB_ARCH=amd64
deb-arm64:
	$(MAKE) deb DEB_ARCH=arm64
deb-armhf:
	$(MAKE) deb DEB_ARCH=armhf

deb-all: deb-amd64 deb-arm64 deb-armhf

upstream:
	@if [ -d _upstream/MAC-Telnet ]; then \
	  echo "_upstream/MAC-Telnet already present — pulling"; \
	  git -C _upstream/MAC-Telnet pull --ff-only; \
	else \
	  git clone --depth 1 https://github.com/haakonnessjoen/MAC-Telnet.git _upstream/MAC-Telnet; \
	fi

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)
