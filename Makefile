# Go project Makefile

# Go commands
GO=go

# Directories
SRC_DIR=./...
BENCH_DIR=./scanner

# Test and benchmark targets
test:
	@$(GO) test $(SRC_DIR)

benchmark:
	@$(GO) test -bench=. -benchmem $(BENCH_DIR)

# Useful Go commands
build:
	@$(GO) build -o bin/app $(SRC_DIR)

run:
	@$(GO) run $(SRC_DIR)

clean:
	@rm -rf bin

format:
	@$(GO) fmt $(SRC_DIR)

vet:
	@$(GO) vet $(SRC_DIR)

mod-tidy:
	@$(GO) mod tidy

.PHONY: test benchmark build run clean format vet mod-tidy
