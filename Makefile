# Makefile — AF_ALG always-slower benchmark suite.
#
# Targets:
#   make afalg_bench    Layer 0 harness        (Linux only: needs <linux/if_alg.h> + OpenSSL for --verify)
#   make openssl_bench  Layer 1 reference      (portable: needs OpenSSL)
#   make fio-engine     Layer 2 fio ioengines  (Linux + fio source tree):
#                         bin/afalg.so (sync, iodepth=1), bin/afalg_async.so (real iodepth)
#   make all            afalg_bench + openssl_bench
#   make clean
#
# The fio engine needs fio's private headers, so point FIO_SRC at a checked-out
# fio source tree:
#   make fio-engine FIO_SRC=/path/to/fio

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDFLAGS ?=
SRC      = src
BIN      = bin

# OpenSSL via pkg-config when available, else assume system paths.
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null || echo -lcrypto)

PTHREAD := -lpthread

.PHONY: all clean afalg_bench openssl_bench fio-engine dirs

all: afalg_bench openssl_bench

dirs:
	@mkdir -p $(BIN)

# Layer 0 — AF_ALG harness (Linux). Links OpenSSL only for the --verify reference.
afalg_bench: dirs
	$(CC) $(CFLAGS) -D_GNU_SOURCE $(OPENSSL_CFLAGS) \
	    $(SRC)/afalg_bench.c $(SRC)/alg_core.c $(SRC)/bench_common.c $(SRC)/ref_crypto.c \
	    $(PTHREAD) $(OPENSSL_LIBS) $(LDFLAGS) -o $(BIN)/afalg_bench

# Layer 1 — OpenSSL reference (portable).
openssl_bench: dirs
	$(CC) $(CFLAGS) -D_GNU_SOURCE $(OPENSSL_CFLAGS) \
	    $(SRC)/openssl_bench.c $(SRC)/bench_common.c $(SRC)/ref_crypto.c \
	    $(PTHREAD) $(OPENSSL_LIBS) $(LDFLAGS) -o $(BIN)/openssl_bench

# Layer 2 — fio external ioengines (shared objects). Requires FIO_SRC.
# Sync and async are separate engines: pick one by the .so you pass to fio.
FIO_CFLAGS = -O2 -Wall -Wextra -std=gnu11 -D_GNU_SOURCE -shared -rdynamic -fPIC \
             -I$(FIO_SRC) -include $(FIO_SRC)/config-host.h
FIO_COMMON = $(SRC)/afalg_fio_common.c $(SRC)/alg_core.c

fio-engine: dirs
ifndef FIO_SRC
	$(error set FIO_SRC=/path/to/fio (a checked-out fio source tree))
endif
	$(CC) $(FIO_CFLAGS) $(SRC)/afalg_fio_engine.c $(FIO_COMMON) \
	    $(LDFLAGS) -o $(BIN)/afalg.so
	$(CC) $(FIO_CFLAGS) $(SRC)/afalg_fio_async.c $(FIO_COMMON) \
	    $(PTHREAD) $(LDFLAGS) -o $(BIN)/afalg_async.so

clean:
	rm -rf $(BIN)
