# Installs the canonical `SitRep` binary plus the platform-named alias:
#   macOS -> MacSitRep      Linux -> LinuxSitRep
#
# PREFIX defaults to ~/.cargo so this lands next to anything installed with
# `cargo install`, and needs no sudo. Override for a system-wide install:
#   sudo make install PREFIX=/usr/local

PREFIX ?= $(HOME)/.cargo
BINDIR  = $(PREFIX)/bin

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  ALIAS = MacSitRep
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
	install -m 755 target/release/SitRep "$(BINDIR)/SitRep"
	@ln -sf SitRep "$(BINDIR)/$(ALIAS)"
	@echo
	@echo "  installed $(BINDIR)/SitRep"
	@echo "  aliased   $(BINDIR)/$(ALIAS) -> SitRep"
	@echo
	@command -v $(ALIAS) >/dev/null 2>&1 \
	  || echo "  note: $(BINDIR) is not on your PATH — add it to run \`$(ALIAS)\` by name."
	@echo

uninstall:
	rm -f "$(BINDIR)/SitRep" "$(BINDIR)/$(ALIAS)"
	@echo "  removed SitRep and $(ALIAS) from $(BINDIR)"

clean:
	cargo clean
