# Build the exec/exit telemetry. Run in WSL.
#   make        build everything into build/
#   make test   run the test script (asks for sudo)
#   make clean  remove build/

CLANG ?= clang
CC ?= gcc
LLVM_STRIP ?= llvm-strip

#linux-tools packages install the real bpftool under /usr/lib/linux-tools.
#/usr/sbin/bpftool wrapper does not work on the WSL kernel.
BPFTOOL ?= $(or $(lastword $(sort $(wildcard /usr/lib/linux-tools/*/bpftool))),bpftool)

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

BUILD := build
LOADER := $(BUILD)/exec_exit_loader

all: $(LOADER)

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp && mv $@.tmp $@

$(BUILD)/exec_exit.bpf.o: src/exec_exit.bpf.c src/common.h src/sensitive_paths.h $(BUILD)/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I$(BUILD) -Isrc -c $< -o $@
	$(LLVM_STRIP) -g $@

$(BUILD)/exec_exit.skel.h: $(BUILD)/exec_exit.bpf.o
	$(BPFTOOL) gen skeleton $< > $@.tmp && mv $@.tmp $@

$(LOADER): src/loader.c src/common.h $(BUILD)/exec_exit.skel.h
	$(CC) -g -O2 -Wall -Wextra -Wno-unused-parameter -Isrc -I$(BUILD) $< -o $@ -lbpf -lelf -lz

test: all
	sudo bash tests/run_test.sh

clean:
	rm -rf $(BUILD)

.PHONY: all test clean
