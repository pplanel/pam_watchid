# pam_watchid — build only; never installs or touches system files.
# Target: macOS 26 (Tahoe), Apple Silicon. Output: build/pam_watchid.so

ARCH      := arm64
MIN_OS    := 26.0
SDK       := $(shell xcrun --show-sdk-path)
CC        := $(shell xcrun -f clang)

SRC       := src/pam_watchid.m
BUILD_DIR := build
MODULE    := $(BUILD_DIR)/pam_watchid.so

# No -fmodules: headers are #imported textually and frameworks linked below,
# so it would only add a non-hermetic ~/Library module cache.
CFLAGS := -arch $(ARCH) -isysroot $(SDK) -mmacosx-version-min=$(MIN_OS) \
          -fobjc-arc -O2 -Wall -Wextra -Werror

LDFLAGS := -dynamiclib -arch $(ARCH) -isysroot $(SDK) \
           -mmacosx-version-min=$(MIN_OS) \
           -Wl,-install_name,pam_watchid.so \
           -lpam \
           -framework Foundation -framework LocalAuthentication \
           -framework SystemConfiguration

HARNESS_SRC := test/harness.m
HARNESS     := $(BUILD_DIR)/harness

.PHONY: all clean verify harness
all: $(MODULE)

$(MODULE): $(SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	@echo "built $@"

harness: $(HARNESS)

$(HARNESS): $(HARNESS_SRC) $(MODULE) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -lpam -framework Foundation -o $@ $<
	@echo "built $@"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

verify: $(MODULE)
	@file $(MODULE)
	@nm -gU $(MODULE) | grep pam_sm_ || (echo "MISSING pam_sm_* exports" && exit 1)
	@codesign -dv $(MODULE) 2>&1 | head -3

clean:
	rm -rf $(BUILD_DIR)
