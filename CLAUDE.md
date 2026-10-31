# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A C benchmark suite measuring the cost of Linux removing zero-copy from AF_ALG (kernel crypto sockets) and the gap between AF_ALG and userspace AES-NI (OpenSSL). Research framing (RQ1–RQ4, hypotheses H1–H4, matrix, methodology) is in `afalg-always-slower-plan.md` (Russian); `README.md` is the operational guide; `RUNNING.md` (Russian) explains which CSV rows to compare for each hypothesis.

## Platform constraint

AF_ALG, `splice`/`vmsplice`, fio and perf are Linux-only. On macOS (the usual dev machine) only `make openssl_bench` and `scripts/plot_results.py` work; `afalg_bench` and the fio engine cannot be built or run locally — they are run on Linux VMs. Don't try to "fix" Linux-only includes (`<linux/if_alg.h>`, `off64_t`, etc.) for macOS.

## Commands

```sh
make all                                  # bin/afalg_bench (Linux) + bin/openssl_bench
make openssl_bench                        # portable; OpenSSL found via pkg-config
make fio-engine FIO_SRC=$PWD/fio-3.35     # bin/afalg.so (sync) + bin/afalg_async.so (async); fio-3.35/ is vendored, untracked, must have run ./configure for config-host.h
make clean

# single data point
./bin/afalg_bench --alg 'cbc(aes)' --method splice --size 64k --iters 5000 [--csv] [--file-backed] [--verify]
./bin/openssl_bench --alg 'cbc(aes)' --size 64k --iters 5000

# matrix smoke test (no root, no perf)
VARIANTS="userspace-aesni afalg-copy" SIZES="4096 65536" REPEATS=3 NO_PERF=1 scripts/run_matrix.sh

# full run on one kernel (Linux, root): build + env checks + afalg/openssl/fio matrices
./run_bench.sh

# analysis
python3 scripts/plot_results.py results/results_*.csv -o figures --summary results/summary.csv
```

There is no test suite or linter. The correctness check is `--verify` (both benches): the timed path's output is compared byte-for-byte against a one-shot OpenSSL result (`src/ref_crypto.c`) before timing. `VERIFY=1` enables it in `run_matrix.sh`; `run_bench.sh` STEP 1a sweeps it. On macOS only `openssl_bench` can actually run.

## Architecture

Layered, bottom-up:

- **`src/alg_core.{c,h}`** — AF_ALG core shared by the standalone bench and the fio engines: `alg_setup`, `build_control` (cmsg for op/IV/AEAD), `op_sendmsg` (copy path), `op_splice` (vmsplice→pipe→splice), `op_splice_file` (splice from a page-cache file — the path the zero-copy removal targets). Both splice variants go through `splice_stream`: one control message with `MSG_MORE`, then chunks of ≤16 pages (sized from the buffer's page offset so unaligned buffers fit the 16-slot pipe; non-final chunks rounded to 16-byte blocks) spliced with `SPLICE_F_MORE`, so the kernel chains the IV and the result is one valid ciphertext/digest. Breaking the block rounding or the MORE flags makes reads hang or the kernel return EINVAL.
- **`src/bench_common.{c,h}`** — timing, latency percentiles, aligned/misaligned buffers, `throughput_mbps` (timed bytes / wall time of the timed phase; workers wait on a `bench_barrier` after warmup so they start together — both benches must use it so rows are comparable), and the **fixed CSV schema** (`struct run_row` + `RUN_CSV_HEADER`). Both benches emit header-less rows with `--csv`; `run_matrix.sh` writes the header and appends perf columns. Changing the schema requires updating `RUN_CSV_HEADER`, `print_csv_row`, `run_matrix.sh`, and `plot_results.py` together; add new bench columns at the end (scripts find `throughput_MBps` etc. by name). `run_matrix.sh` refuses to append to a CSV with a different header.
- **`src/afalg_bench.c`** (Layer 0) / **`src/openssl_bench.c`** (Layer 1) — pthread workers sweeping size/alignment/threads. Unkeyed hashes must not get `ALG_SET_KEY` (the kernel rejects it); only ciphers and `hmac(...)` are keyed. The `variant` label is derived from method: `sendmsg`→`afalg-copy`, `splice`→`afalg-zc`, `--file-backed`→`afalg-zc-file`, OpenSSL→`userspace-aesni`.
- **Layer 2 fio engines** — two separate `.so`s sharing `src/afalg_fio_common.{c,h}` (options table, context setup, per-io_u op): `afalg_fio_engine.c` → `bin/afalg.so` is `FIO_SYNCIO` (iodepth effectively 1); `afalg_fio_async.c` → `bin/afalg_async.so` runs a per-job pool of `iodepth` threads, each with its own AF_ALG socket, behind queue/commit/getevents/event. fio loads the `ioengine` symbol, so one engine per `.so`. They use fio private headers (`-I$FIO_SRC -include config-host.h`), so build against the exact fio tree that runs them; check `struct ioengine_ops`/`FIO_IOOPS_VERSION` against `engines/skeleton_external.c` if fields drift. fio `write`=encrypt, `read`=decrypt. `run_bench.sh` uses sync for qd=1 and async for qd>1 (`FIO_ASYNC=0` forces sync).
- **`scripts/run_matrix.sh`** (Layer 3) — sweeps the matrix via env knobs (`VARIANTS ALGS SIZES ALIGNS THREADS OPS KEYBITS REPEATS ITERS WARMUP PIN_CPU GOVERNOR NO_PERF PAUSE PERF_LAST_N PERF_EVENTS VERIFY`), optionally wraps runs in `perf stat`, writes `results/results_$(uname -r).csv`. Events beyond the base four become extra CSV columns.
- **`run_bench.sh`** — top-level one-kernel driver: builds everything (fio engine against `fio-3.35/`), raises `net.core.wmem_max` (sendmsg >~200 KiB deadlocks in `af_alg_wait_for_wmem` otherwise), auto-detects whether the kernel still has zero-copy (splice/sendmsg throughput ratio), runs afalg/openssl/fio matrices with pauses and cache drops between phases. Optional `HOST_SSH` for host-side cache cleanup.

## Key experimental invariant

The same userspace binary and script are run on a **pre-fix kernel** and a **post-fix kernel**; results are separated only by the `kernel` column (`uname -r`). The fix's cost is `afalg-zc` old vs new kernel on identical alg/size/alignment/threads/op cells. Keep code changes from making the two runs non-comparable.

## AF_ALG socket limits (all needed for payloads up to 16 MiB; `run_bench.sh` sets them, `alg_core` warns)

- `net.core.wmem_max` → SO_SNDBUF. Too small: sendmsg above ~208 KiB **hangs** in `af_alg_wait_for_wmem`.
- `net.core.rmem_max` → SO_RCVBUF. Too small: the kernel's AEAD recvmsg silently splits one message into several GCM operations inside a single `read()` (full length, wrong output). `op_sendmsg` therefore refuses AEAD messages larger than `c->rcvbuf` with EMSGSIZE.
- `net.core.optmem_max` (per netns) → AF_ALG scatterlists. Too small (128 KiB default): 16 MiB sendmsg fails with ENOMEM.

## Caveats

- AEAD (`gcm(aes)`) is experimental: copy path only; `op_splice` returns `ENOTSUP` for AEAD; `--verify` covers AEAD encrypt without AAD only.
- fio engines set `FIO_DISKLESSIO`; without it fio lays out real data files (256 MiB per job) on disk.
