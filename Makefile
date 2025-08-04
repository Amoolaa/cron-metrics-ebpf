# Compiler and tool options
CLANG ?= clang
GO ?= go
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/g; s/aarch64/arm64/g')

# Output binary name
TARGET = cron-ebpf

# eBPF source and object files
BPF_SRC = cron_metrics.c
BPF_OBJ = $(BPF_SRC:.c=.o)

.PHONY: all
all: generate build

.PHONY: generate
generate: vmlinux.h
	$(GO) generate

.PHONY: build
build: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) $(GO) build -o $(TARGET)

.PHONY: run
run: build
	sudo ./$(TARGET)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_OBJ): $(BPF_SRC) vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $(BPF_SRC) -o $(BPF_OBJ)

.PHONY: clean
clean:
	rm -f $(TARGET)
	rm -f $(BPF_OBJ)
	rm -f *_bpf*.go
	rm -f *_bpf*.o
	rm -f vmlinux.h

.PHONY: deps
deps:
	$(GO) mod tidy
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

.PHONY: test
test:
	$(GO) test -v ./...

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all        - Generate eBPF code, build Go program (default)"
	@echo "  generate   - Generate Go bindings for eBPF code"
	@echo "  build      - Build the Go program"
	@echo "  run        - Build and run the program (requires sudo)"
	@echo "  clean      - Remove generated files and binaries"
	@echo "  deps       - Install Go dependencies"
	@echo "  test       - Run Go tests"
	@echo ""
	@echo "Environment variables:"
	@echo "  CLANG      - Path to clang compiler (default: clang)"
	@echo "  GO         - Path to go compiler (default: go)"
	@echo "  ARCH       - Target architecture (default: current architecture)"
