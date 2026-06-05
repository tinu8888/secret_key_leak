# Makefile: build the kit's FIRST-ORDER MASKED simpleserial-aes target.
#
# ⚠️ APPROVAL GATE (human-approved): running `make` here invokes the ARM toolchain to build
# firmware that will be flashed to hardware. The compile is non-gated; flashing and HIL verify
# are APPROVAL-GATED. Do NOT flash without separate approval.
#
# Same wrapper pattern as ../aes-unprotected/Makefile: it does NOT vendor ChipWhisperer
# sources; it invokes the kit's own makefile for the SAME `simpleserial-aes` example, only
# selecting the masked crypto (CRYPTO_TARGET=MASKEDAES). The masked firmware MUST expose the
# identical simpleserial command/response ('k'/'p') + GPIO trigger semantics as the unprotected
# build (only the internal AES leakage differs), so the US1/US2 attacks run UNCHANGED.
#
# ============================ KNOWN BLOCKER (see README.md) ============================
# CRYPTO_TARGET=MASKEDAES does NOT support the CW-Nano's STM32F0 (Cortex-M0). The kit's
# crypto/Makefile.maskedaes offers: ANSSI (Cortex-M4: stm32f3/f4/l4/... or AVR only),
# RIOUBSAES and KNARFRANK (bit-sliced/higher-order; their source dirs are not present in this
# SDK clone). Building for PLATFORM=CWNANO fails with, e.g.:
#   crypto/Makefile.maskedaes:62: *** Unsupported platform/hal for ANSSI masked AES crypto.
# So a masked baseline on THIS board needs either a Cortex-M4 target (e.g. CW308+STM32F4) or a
# Cortex-M0-compatible first-order-masked AES added to the kit tree. See README.md "Status".
# ======================================================================================
#
# Required variables (set on the command line / env, after toolchain + board recorded):
#   CW_FW_DIR      Path to the ChipWhisperer firmware tree, i.e. <chipwhisperer>/firmware/mcu
#   PLATFORM       Target whose HAL is supported by the chosen masked impl (NOT CWNANO/STM32F0)
#   CRYPTO_TARGET  MASKEDAES (default here)
#   CRYPTO_OPTIONS Masked implementation selector, e.g. ANSSI (Cortex-M4), REQUIRED by the kit
#
# Usage:
#   make show                                  # print resolved config (safe; no toolchain run)
#   make PLATFORM=CW308_STM32F4 CRYPTO_OPTIONS=ANSSI   # build → simpleserial-aes-<PLATFORM>.hex

CRYPTO_TARGET ?= MASKEDAES
TARGET        := simpleserial-aes
SELF_DIR      := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: show help build clean check-vars

help:
	@echo "aes-masked build wrapper (⚠️ flash is approval-gated)."
	@echo "Targets: show | build (default) | clean"
	@echo "Required: CW_FW_DIR=<chipwhisperer>/firmware/mcu  PLATFORM=<masked-capable target>"
	@echo "          CRYPTO_TARGET=MASKEDAES  CRYPTO_OPTIONS=<impl, e.g. ANSSI>"
	@echo "NOTE: MASKEDAES does NOT support CWNANO/STM32F0 (Cortex-M0). See README.md Status."

show:
	@echo "TARGET        = $(TARGET)"
	@echo "CW_FW_DIR     = $(CW_FW_DIR)"
	@echo "PLATFORM      = $(PLATFORM)"
	@echo "CRYPTO_TARGET = $(CRYPTO_TARGET)  (first-order masked AES)"
	@echo "CRYPTO_OPTIONS= $(CRYPTO_OPTIONS)  (masked impl selector, REQUIRED, e.g. ANSSI)"
	@echo "SELF_DIR      = $(SELF_DIR)"

check-vars:
	@if [ -z "$(CW_FW_DIR)" ]; then \
	  echo "ERROR: CW_FW_DIR is unset. Point it at <chipwhisperer>/firmware/mcu (see README.md)."; exit 2; fi
	@if [ -z "$(PLATFORM)" ]; then \
	  echo "ERROR: PLATFORM is unset. Use a masked-capable target (NOT CWNANO/STM32F0)."; exit 2; fi
	@if [ ! -d "$(CW_FW_DIR)/$(TARGET)" ]; then \
	  echo "ERROR: $(CW_FW_DIR)/$(TARGET) not found. Check CW_FW_DIR against your installed SDK."; exit 2; fi

# Default target. Delegates to the kit makefile (same simpleserial-aes target, masked crypto),
# then copies the .hex back here. ⚠️ Flashing the result is the gated step.
build: check-vars
	$(MAKE) -C "$(CW_FW_DIR)/$(TARGET)" PLATFORM=$(PLATFORM) CRYPTO_TARGET=$(CRYPTO_TARGET) CRYPTO_OPTIONS=$(CRYPTO_OPTIONS)
	@cp -f "$(CW_FW_DIR)/$(TARGET)/$(TARGET)-$(PLATFORM).hex" "$(SELF_DIR)/" 2>/dev/null || true
	@echo "Built. Artifact (if produced): $(SELF_DIR)/$(TARGET)-$(PLATFORM).hex"
	@echo "Record the .hex path + firmware_hash in notes/setup-verified.md before flashing."

.DEFAULT_GOAL := build

clean:
	@rm -f "$(SELF_DIR)/$(TARGET)"-*.hex "$(SELF_DIR)/$(TARGET)"-*.elf
	-@[ -n "$(CW_FW_DIR)" ] && [ -d "$(CW_FW_DIR)/$(TARGET)" ] && \
	  $(MAKE) -C "$(CW_FW_DIR)/$(TARGET)" clean PLATFORM=$(PLATFORM) || true
	@echo "Cleaned local artifacts."
