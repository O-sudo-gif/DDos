# Makefile for TCP SYN Flood Tool

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -std=c99
LDFLAGS = -lpthread
TARGET = syn
SOURCE = syn.c

# Debug build flags
DEBUG_CFLAGS = -g -DDEBUG -O0

# Installation paths
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

# Default target
all: $(TARGET)

# Build optimized release
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)
	@echo "[+] Build complete: $(TARGET)"

# Debug build
debug: CFLAGS = $(DEBUG_CFLAGS)
debug: $(TARGET)
	@echo "[+] Debug build complete: $(TARGET)"

# Static build
static: CFLAGS += -static
static: $(TARGET)
	@echo "[+] Static build complete: $(TARGET)"

# Install
install: $(TARGET)
	@echo "[*] Installing $(TARGET) to $(BINDIR)..."
	@mkdir -p $(BINDIR)
	@cp $(TARGET) $(BINDIR)/
	@chmod +x $(BINDIR)/$(TARGET)
	@echo "[+] Installation complete"

# Uninstall
uninstall:
	@echo "[*] Uninstalling $(TARGET)..."
	@rm -f $(BINDIR)/$(TARGET)
	@echo "[+] Uninstallation complete"

# Clean build artifacts
clean:
	@echo "[*] Cleaning build artifacts..."
	@rm -f $(TARGET) $(TARGET).o
	@echo "[+] Clean complete"

# Run basic test (requires root)
test: $(TARGET)
	@echo "[*] Running basic test (requires root)..."
	@echo "[!] This will send packets to 127.0.0.1:80 for 5 seconds"
	@echo "[!] Press CTRL+C to stop early"
	@sleep 2
	@sudo ./$(TARGET) 127.0.0.1 80 10 5 1000 || true

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Build optimized release (default)"
	@echo "  debug    - Build with debug symbols"
	@echo "  static   - Build static binary"
	@echo "  install  - Install to $(BINDIR)"
	@echo "  uninstall - Remove from $(BINDIR)"
	@echo "  clean    - Remove build artifacts"
	@echo "  test     - Run basic test (requires root)"
	@echo "  help     - Show this help message"

.PHONY: all debug static install uninstall clean test help

