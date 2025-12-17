# ============================================================
# PDM Detection Makefile
# ============================================================

CC := gcc

# ------------------------------------------------------------
# ONNX Runtime (override from command line if needed)
#   make ORT_DIR=/opt/onnxruntime-linux-x64-1.22.0
# ------------------------------------------------------------
ORT_DIR ?= $(HOME)/onnxruntime-linux-x64-1.22.0

ORT_INC   := -I$(ORT_DIR)/include
ORT_LIB   := -L$(ORT_DIR)/lib
ORT_RPATH := -Wl,-rpath,$(ORT_DIR)/lib

# ------------------------------------------------------------
# Common flags
# ------------------------------------------------------------
COMMON_CFLAGS := -fPIC \
                 -fno-stack-protector \
                 -fno-builtin \
                 -fno-jump-tables \
                 -fno-common \
                 -pthread

# ------------------------------------------------------------
# Targets
# ------------------------------------------------------------
DETECTION_SO := PDM-detection.so
SCHEME_SO    := PDM-scheme3+.so
VICTIM_BIN   := example/victim

.PHONY: all clean

all: $(DETECTION_SO) $(SCHEME_SO) $(VICTIM_BIN)

# ============================================================
# PDM-detection.so (ONNX Runtime, optimized)
# ============================================================
$(DETECTION_SO): PDM-detection.c
	$(CC) -O3 -march=native $(COMMON_CFLAGS) -shared -o $@ $< \
	$(ORT_INC) $(ORT_LIB) -lonnxruntime $(ORT_RPATH)

# ============================================================
# PDM-scheme3+.so (no ONNX)
# ============================================================
$(SCHEME_SO): PDM-scheme3+.c
	$(CC) -O0 $(COMMON_CFLAGS) -shared -o $@ $<

# ============================================================
# Example victim binary
# ============================================================
$(VICTIM_BIN): example/victim.c
	$(CC) -O2 -o $@ $< -lrt

# ============================================================
# Cleanup
# ============================================================
clean:
	rm -f $(DETECTION_SO) $(SCHEME_SO) $(VICTIM_BIN)
