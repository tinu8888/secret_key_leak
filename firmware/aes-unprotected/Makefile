# Makefile: build the kit's UNPROTECTED simpleserial-aes target.
#
# ⚠️ APPROVAL GATE (human-approved): running `make` here invokes the ARM toolchain to build
# firmware that will be flashed to hardware. Do NOT run this until:
#   1. the ARM toolchain is approved + installed, and
#   2. the exact board/PLATFORM is recorded in notes/hardware.md.
# Building, flashing, and HIL verify are approval-gated.
#
# This file does NOT vendor ChipWhisperer sources. It is a thin wrapper that invokes the
# kit's own makefile for the `simpleserial-aes` example, selecting the unprotected
# (non-masked) AES + your target PLATFORM. See README.md (Option A/B) and BUILD.md.
#
# Required variables (set on the command line or your environment, after toolchain + board recorded):
#   CW_FW_DIR      Path to the ChipWhisperer firmware tree, i.e. <chipwhisperer>/firmware/mcu
#   PLATFORM       Your exact target, e.g. CW308_STM32F4 | CWLITEARM | CWNANO
#   CRYPTO_TARGET  Unprotected AES C impl shipped with the kit (default: TINYAES128C)
#
# Usage (ALL gated, human-approved, logged in notes/approvals.md):
#   make PLATFORM=CW308_STM32F4              # build → simpleserial-aes-<PLATFORM>.hex here
#   make clean                               # remove local build artifacts
#   make show                                # print resolved config (safe; no toolchain run)

CRYPTO_TARGET ?= TINYAES128C
TARGET        := simpleserial-aes
SELF_DIR      := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# `show` and `help` are safe and must work WITHOUT the toolchain or hardware.
.PHONY: show help build clean check-vars

help:
	@echo "aes-unprotected build wrapper (⚠️ build/flash are approval-gated)."
	@echo "Targets: show | build (default) | clean"
	@echo "Required: CW_FW_DIR=<chipwhisperer>/firmware/mcu  PLATFORM=<your target>"
	@echo "Optional: CRYPTO_TARGET (default TINYAES128C)"
	@echo "See README.md and BUILD.md. Do not run 'build' before toolchain + board approval."

show:
	@echo "TARGET        = $(TARGET)"
	@echo "CW_FW_DIR     = $(CW_FW_DIR)"
	@echo "PLATFORM      = $(PLATFORM)"
	@echo "CRYPTO_TARGET = $(CRYPTO_TARGET)  (unprotected AES; masking lives in firmware/aes-masked)"
	@echo "SELF_DIR      = $(SELF_DIR)"

check-vars:
	@if [ -z "$(CW_FW_DIR)" ]; then \
	  echo "ERROR: CW_FW_DIR is unset. Point it at <chipwhisperer>/firmware/mcu (see README.md)."; exit 2; fi
	@if [ -z "$(PLATFORM)" ]; then \
	  echo "ERROR: PLATFORM is unset. Set your exact target (recorded in notes/hardware.md)."; exit 2; fi
	@if [ ! -d "$(CW_FW_DIR)/$(TARGET)" ]; then \
	  echo "ERROR: $(CW_FW_DIR)/$(TARGET) not found. Check CW_FW_DIR against your installed SDK."; exit 2; fi

# Default target. Delegates to the kit makefile, then copies the .hex back here.
# This is the ⚠️ approval-gated build step, only after toolchain approval + board recorded.
build: check-vars
	$(MAKE) -C "$(CW_FW_DIR)/$(TARGET)" PLATFORM=$(PLATFORM) CRYPTO_TARGET=$(CRYPTO_TARGET)
	@cp -f "$(CW_FW_DIR)/$(TARGET)/$(TARGET)-$(PLATFORM).hex" "$(SELF_DIR)/" 2>/dev/null || true
	@echo "Built. Artifact (if produced): $(SELF_DIR)/$(TARGET)-$(PLATFORM).hex"
	@echo "Record the .hex path + firmware_hash in notes/setup-verified.md before flashing."

.DEFAULT_GOAL := build

clean:
	@rm -f "$(SELF_DIR)/$(TARGET)"-*.hex "$(SELF_DIR)/$(TARGET)"-*.elf
	-@[ -n "$(CW_FW_DIR)" ] && [ -d "$(CW_FW_DIR)/$(TARGET)" ] && \
	  $(MAKE) -C "$(CW_FW_DIR)/$(TARGET)" clean PLATFORM=$(PLATFORM) || true
	@echo "Cleaned local artifacts."
