# AF_ALG "always slower" — benchmark suite

Measures how much removing zero-copy from Linux's AF_ALG (kernel crypto sockets,
May 2026) cost userspace, and how far AF_ALG sits behind optimized userspace
crypto (AES-NI). The full research framing — motivation, research questions
RQ1–RQ4, hypotheses H1–H4, the experiment matrix, methodology and limitations —
lives in [`afalg-always-slower-plan.md`](afalg-always-slower-plan.md). This
README is the operational guide.

> **Platform:** AF_ALG, `splice`/`vmsplice`, `fio` and `perf` are Linux-only.
> The AF_ALG harness and the fio engine build and run **only on Linux**. The
> OpenSSL reference bench and the Python plotting are portable (they build/run
> on macOS too, which is useful for developing the analysis side).

## Layers (bottom-up)

| Layer | File | Role |
| --- | --- | --- |
| 0 | `src/alg_core.{c,h}` | AF_ALG crypto core: `alg_setup`, `build_control`, `op_sendmsg`, `op_splice`. Shared by layers 0 and 2. |
| 0 | `src/afalg_bench.c` | Standalone harness: copy vs zero-copy, size/alignment/thread sweeps, throughput + latency. |
| 1 | `src/openssl_bench.c` | Reference baseline: OpenSSL EVP (AES-NI / ARMv8 crypto). The "always slower" comparator. |
| 2 | `src/afalg_fio_engine.c` | fio external ioengine (skeleton) wrapping the crypto core for numjobs/iodepth/AIO + latency percentiles. |
| 3 | `scripts/run_matrix.sh` | Orchestration: sweeps the matrix, wraps runs with `perf stat`, writes `results/results_$(uname -r).csv`. |
| — | `src/bench_common.{c,h}` | Timing, latency percentiles, buffers, CSV schema (shared by both benches). |
| — | `scripts/plot_results.py` | Aggregates repeats → mean + 95% CI, writes a summary CSV and charts. |

The key move: `afalg_bench --method splice` run on a **pre-fix kernel** (real
zero-copy) and a **post-fix kernel** (splice copies internally) isolates the
cost of the fix — the userspace code is byte-for-byte identical on both. Rows
are compared cell-for-cell via the `kernel` column.

## Build

```sh
make all            # afalg_bench (Linux) + openssl_bench (portable)
make afalg_bench    # Layer 0, Linux only (needs <linux/if_alg.h>)
make openssl_bench  # Layer 1, needs OpenSSL dev headers
```

Binaries land in `bin/`. On macOS, `make openssl_bench` works out of the box
(`brew install openssl`, the Makefile finds it via `pkg-config`); `make
afalg_bench` will not — AF_ALG does not exist off Linux.

### fio engine (Layer 2)

The engine uses fio's private headers, which change between releases, so build
it against the fio source tree you will run:

```sh
make fio-engine FIO_SRC=/path/to/fio      # -> bin/afalg.so
```

Then drive it with fio:

```sh
fio --ioengine=external:./bin/afalg.so --name=enc --rw=write \
    --afalg_alg='cbc(aes)' --afalg_type=skcipher --afalg_method=sendmsg \
    --afalg_keybits=128 --bs=64k --size=256m --numjobs=4 --iodepth=1
```

Options: `afalg_alg`, `afalg_type` (skcipher/hash/aead), `afalg_method`
(sendmsg/splice), `afalg_keybits`. fio `write` → encrypt, `read` → decrypt;
hashes ignore direction. Cross-check `struct ioengine_ops` /
`FIO_IOOPS_VERSION` against `engines/skeleton_external.c` in your fio tree if a
field name drifts.

## Run

### A single point

```sh
./bin/afalg_bench --alg 'cbc(aes)' --method sendmsg --size 64k --iters 5000
./bin/afalg_bench --alg 'cbc(aes)' --method splice  --size 64k --iters 5000  # pre-fix kernel only gives true ZC
./bin/openssl_bench --alg 'cbc(aes)' --size 64k --iters 5000
```

Add `--csv` for a machine-readable row, `--header` to print the column header.
See `--help` on either bench for the full option list (`--type`, `--op`,
`--aligned/--unaligned`, `--threads`, `--keybits`, AEAD `--taglen/--assoclen`).

### The whole matrix

```sh
# full defaults (plan matrix), with perf + 5 repeats/cell:
sudo GOVERNOR=1 PIN_CPU=2 scripts/run_matrix.sh

# quick smoke run, no perf, no root:
VARIANTS="userspace-aesni afalg-copy" SIZES="4096 65536 1048576" \
  REPEATS=3 NO_PERF=1 scripts/run_matrix.sh
```

Output: `results/results_$(uname -r).csv`, one row per run. Run the **same
script on both kernels** (old zero-copy build, new fixed build) to populate the
two-kernel comparison. Env knobs are documented in the script header
(`VARIANTS ALGS SIZES ALIGNS THREADS OPS KEYBITS REPEATS ITERS WARMUP PIN_CPU
GOVERNOR NO_PERF`).

### Analyze

```sh
python3 scripts/plot_results.py results/results_*.csv -o figures --summary results/summary.csv
```

Produces `results/summary.csv` (per-cell mean + 95% CI) and PNGs per
alg × alignment × threads × metric, with a series per `(variant, kernel)` — so
the fix's cost (`afalg-zc` old vs new kernel) and the AF_ALG↔userspace gap read
straight off the chart. Needs `matplotlib` for the PNGs; the summary CSV is
written regardless.

## Methodology (for publishable numbers)

Set by `run_matrix.sh` when asked (needs root); see plan §Методология.

- `GOVERNOR=1` → performance governor + turbo off (`intel_pstate/no_turbo`).
- `PIN_CPU=n` → `taskset -c n` to pin, reduce migration/NUMA noise.
- Warmup iterations discarded (`--warmup`); ≥5 repeats/cell for CIs.
- `perf stat -e cycles,instructions,cache-misses,LLC-load-misses` → cycles/byte
  and memory pressure, merged into the CSV automatically.

## Status vs. plan

- **Phase 0** (single kernel, harness + reference, size curve): ready — build
  and run both benches.
- **Phase 1** (two kernels, isolated fix cost): run `run_matrix.sh` on each
  kernel; compare on the `kernel` column.
- **Phase 2** (fio parallelism): engine skeleton in place; build against your
  fio tree.
- **Phase 3** (embedded / no AES-NI): disable acceleration out-of-band
  (e.g. `OPENSSL_ia32cap=~0x200000000000000` on x86) and re-run.

**Coverage / caveats** (plan §Ограничения): skcipher and hash are fully
exercised; AEAD (`gcm(aes)`) is implemented but experimental on the AF_ALG side
(the copy path only; `op_splice` returns `ENOTSUP` for AEAD). Payloads above the
zero-copy ceiling (16 pages ≈ 64 KB) are chunked — valid for throughput timing,
not a single valid ciphertext under CBC chaining. Ciphertext correctness is a
separate concern from timing and is not validated in the hot loop.
