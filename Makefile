# Installs the canonical `sitrep` binary plus the platform-named alias:
#   macOS -> MacSitrep      Linux -> LinuxSitRep
#
# PREFIX defaults to ~/.cargo so this lands next to anything installed with
# `cargo install`, and needs no sudo. Override for a system-wide install:
#   sudo make install PREFIX=/usr/local

PREFIX ?= $(HOME)/.cargo
BINDIR  = $(PREFIX)/bin

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  ALIAS = MacSitrep
else
  ALIAS = LinuxSitRep
endif

.PHONY: all build test lint install uninstall clean

all: build

build:
	cargo build --release

test:
	cargo test

lint:
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check

install: build
	@mkdir -p "$(BINDIR)"
	install -m 755 target/release/sitrep "$(BINDIR)/sitrep"
	@ln -sf sitrep "$(BINDIR)/$(ALIAS)"
	@echo
	@echo "  installed $(BINDIR)/sitrep"
	@echo "  aliased   $(BINDIR)/$(ALIAS) -> sitrep"
	@echo
	@command -v $(ALIAS) >/dev/null 2>&1 \
	  || echo "  note: $(BINDIR) is not on your PATH — add it to run \`$(ALIAS)\` by name."
	@echo

uninstall:
	rm -f "$(BINDIR)/sitrep" "$(BINDIR)/$(ALIAS)"
	@echo "  removed sitrep and $(ALIAS) from $(BINDIR)"

clean:
	cargo clean
