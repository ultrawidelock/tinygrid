# tinygrid host build: unit tests, the simulation node and the interop run.
#
# CC is honoured. On a machine whose default cc is not the tool you want:
#   make test CC=/usr/bin/clang
# MBEDTLS_PREFIX is where Mbed TLS 3.6 is installed (include/ and lib/).
# OT_CLI is an ot-cli-ftd built for OpenThread's simulation platform.

export LC_ALL := C
BUILD := build/host

CSTD := -std=c11 -O1 -g
# Zephyr's clang warning_base, as tinytalk compiles under, plus -Werror.
WARN := -Wall -Wformat -Wformat-security -Wno-format-zero-length \
	-Wno-unused-but-set-variable -Wno-typedef-redefinition \
	-Wno-deprecated-non-prototype -Wdouble-promotion -Wno-pointer-sign \
	-Wpointer-arith -Werror
SAN := -fsanitize=address,undefined -fno-sanitize-recover=all

MBEDTLS_PREFIX ?= $(shell brew --prefix mbedtls@3 2>/dev/null || echo /usr)
CRYPTO_INC := -I$(MBEDTLS_PREFIX)/include
CRYPTO_LIB := -L$(MBEDTLS_PREFIX)/lib -lmbedcrypto

CORE := $(wildcard src/*.c) ports/psa/tg_psa.c
HDRS := $(wildcard include/tinygrid/*.h src/*.h ports/host/*.h)
INCS := -Iinclude -Iports/host $(CRYPTO_INC)

OT_CLI ?= build/ot-sim/examples/apps/cli/ot-cli-ftd

.PHONY: test sim interop clean

test: $(BUILD)/tests
	$(BUILD)/tests
	@# The smallest build: rx-on only, no resolver, no multicast.
	$(CC) $(CSTD) $(WARN) -Iinclude -DTG_SED=0 -DTG_DNS=0 -DTG_MCAST=0 -fsyntax-only \
		$(filter-out src/tg_dns.c,$(wildcard src/*.c))

$(BUILD)/tests: $(CORE) $(wildcard tests/host/*.c) $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CSTD) $(WARN) $(SAN) $(INCS) -Isrc -D_DEFAULT_SOURCE $(CORE) tests/host/*.c \
		-o $@ $(CRYPTO_LIB)

sim: $(BUILD)/tg_node

$(BUILD)/tg_node: $(CORE) ports/host/tg_host.c tests/sim/tg_node.c $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CSTD) $(WARN) $(SAN) $(INCS) $(CORE) ports/host/tg_host.c tests/sim/tg_node.c \
		-o $@ $(CRYPTO_LIB)

# The same node with a 12 s child timeout, so keep-alive and parent loss
# happen inside a test run.
$(BUILD)/tg_node_fast: $(CORE) ports/host/tg_host.c tests/sim/tg_node.c $(HDRS)
	@mkdir -p $(BUILD)
	$(CC) $(CSTD) $(WARN) $(SAN) -DTG_CHILD_TIMEOUT_S=12u $(INCS) $(CORE) ports/host/tg_host.c \
		tests/sim/tg_node.c -o $@ $(CRYPTO_LIB)

interop: $(BUILD)/tg_node $(BUILD)/tg_node_fast
	python3 -I tests/sim/interop.py --ot $(OT_CLI) --tg $(BUILD)/tg_node
	python3 -I tests/sim/interop.py --ot $(OT_CLI) --tg $(BUILD)/tg_node --poll 500
	python3 -I tests/sim/interop.py --ot $(OT_CLI) --tg $(BUILD)/tg_node_fast --robust

clean:
	rm -rf $(BUILD)
