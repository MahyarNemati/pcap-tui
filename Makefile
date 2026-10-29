# Default feature set: no libpcap, no root. Everything below works on a
# machine with neither, which is the point.
CARGO ?= cargo

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the debug binary
	$(CARGO) build

.PHONY: release
release: ## Build the optimised binary
	$(CARGO) build --release

.PHONY: test
test: ## Run every test
	$(CARGO) test --all-targets

.PHONY: lint
lint: ## Check formatting and run clippy with warnings as errors
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --all-targets -- -D warnings
	$(CARGO) clippy --all-targets --features live -- -D warnings

.PHONY: fmt
fmt: ## Reformat the source
	$(CARGO) fmt --all

.PHONY: sample
sample: ## Write sample.pcap, so the viewer can be tried immediately
	$(CARGO) run --quiet --example sample-capture -- sample.pcap

.PHONY: demo
demo: sample ## Write a sample capture and open it
	$(CARGO) run --quiet -- sample.pcap

.PHONY: summary
summary: sample ## Write a sample capture and print its summary
	$(CARGO) run --quiet -- summary sample.pcap

.PHONY: live
live: ## Build with live capture support (needs libpcap)
	$(CARGO) build --release --features live

.PHONY: audit
audit: ## Check dependencies for known vulnerabilities
	$(CARGO) audit

.PHONY: ci
ci: lint test ## Everything CI runs

.PHONY: clean
clean:
	$(CARGO) clean
	rm -f sample.pcap
