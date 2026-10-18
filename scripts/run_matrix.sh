#!/usr/bin/env bash
#
# run_matrix.sh — Layer 3 orchestration.
#
# Sweeps the experiment matrix (plan, "Матрица экспериментов"), wraps each run
# with `perf stat` to capture cycles / cache behaviour, and writes one merged
# CSV row per run into results/results_$(uname -r).csv. The same script runs on
# the old (zero-copy) and new (copy) kernel; rows are compared cell-for-cell via
# the `kernel` column.
#
# Honesty of measurement depends on the methodology knobs below — enable them
# (needs root for governor/turbo/pinning) for publishable numbers.
#
# Usage:
#   scripts/run_matrix.sh                 # full matrix with defaults
#   SIZES="4096 65536" REPEATS=3 scripts/run_matrix.sh   # quick smoke run
#   PIN_CPU=2 GOVERNOR=1 scripts/run_matrix.sh           # apply pinning/governor
#
# Env knobs (all optional):
#   VARIANTS   space list: afalg-copy afalg-zc userspace-aesni   (default all)
#   ALGS       e.g. "cbc(aes) sha256 gcm(aes)"
#   SIZES      bytes, e.g. "64 256 1024 ... 16777216"
#   ALIGNS     "aligned unaligned"
#   THREADS    "1 2 4"
#   OPS        "enc" / "enc dec"
#   KEYBITS    "128" / "128 256"
#   REPEATS    repeats per cell (default 10)
#   ITERS      timed iters per repeat (default 10000)
#   WARMUP     warmup iters (default 1000)
#   PIN_CPU    taskset CPU id (unset = no pinning)
#   GOVERNOR   1 = set performance governor + disable turbo (needs root)
#   NO_PERF    1 = skip perf wrapping
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/bin"
RESULTS_DIR="$ROOT/results"
KREL="$(uname -r)"
OUT="$RESULTS_DIR/results_${KREL}.csv"

# ---- defaults (full factorial, but trimmed to the plan's headline factors) ----
VARIANTS="${VARIANTS:-afalg-copy afalg-zc userspace-aesni}"
ALGS="${ALGS:-cbc(aes) sha256}"
SIZES="${SIZES:-64 256 1024 4096 16384 65536 262144 1048576 4194304 16777216}"
ALIGNS="${ALIGNS:-aligned unaligned}"
THREADS="${THREADS:-1}"
OPS="${OPS:-enc}"
KEYBITS="${KEYBITS:-128}"
REPEATS="${REPEATS:-10}"
ITERS="${ITERS:-10000}"
WARMUP="${WARMUP:-1000}"
PIN_CPU="${PIN_CPU:-}"
GOVERNOR="${GOVERNOR:-0}"
NO_PERF="${NO_PERF:-0}"

PERF_EVENTS="cycles,instructions,cache-misses,LLC-load-misses"

mkdir -p "$RESULTS_DIR"

# ---- locate binaries ----
have_afalg=0; have_openssl=0
[ -x "$BIN/afalg_bench" ]   && have_afalg=1
[ -x "$BIN/openssl_bench" ] && have_openssl=1
if [ "$have_afalg" = 0 ] && [ "$have_openssl" = 0 ]; then
    echo "error: no binaries in $BIN. Run 'make all' first." >&2
    exit 1
fi

# ---- perf availability ----
use_perf=0
if [ "$NO_PERF" != 1 ] && command -v perf >/dev/null 2>&1; then
    if perf stat -x, -e cycles true >/dev/null 2>&1; then
        use_perf=1
    else
        echo "note: perf present but not usable (perf_event_paranoid?); continuing without it." >&2
    fi
fi

# ---- methodology: performance governor + no turbo ----
restore_governor() { :; }
if [ "$GOVERNOR" = 1 ]; then
    if [ "$(id -u)" = 0 ]; then
        for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
            [ -w "$g" ] && echo performance > "$g" 2>/dev/null || true
        done
        [ -w /sys/devices/system/cpu/intel_pstate/no_turbo ] && \
            echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true
        echo "methodology: performance governor set, turbo disabled." >&2
    else
        echo "warning: GOVERNOR=1 requires root; skipping." >&2
    fi
fi

# ---- CSV header (bench schema + orchestration/perf columns) ----
BENCH_HEADER="$("$BIN/afalg_bench" --header 2>/dev/null || "$BIN/openssl_bench" --header)"
if [ ! -f "$OUT" ]; then
    echo "${BENCH_HEADER},repeat,cycles,instructions,cache_misses,llc_load_misses,cpu_seconds,cycles_per_byte" > "$OUT"
    echo "created $OUT" >&2
else
    echo "appending to existing $OUT" >&2
fi

# Map a variant to (binary, method, extra-args).
bin_for_variant() {
    case "$1" in
        afalg-copy)       echo "afalg_bench sendmsg" ;;
        afalg-zc)         echo "afalg_bench splice" ;;
        userspace-aesni)  echo "openssl_bench evp" ;;
        *) echo "" ;;
    esac
}

type_for_alg() {
    case "$1" in
        sha*|md5) echo "hash" ;;
        gcm*)     echo "aead" ;;
        *)        echo "skcipher" ;;
    esac
}

run_one() {
    local variant="$1" alg="$2" size="$3" align="$4" thr="$5" op="$6" kb="$7" rep="$8"
    local spec; spec="$(bin_for_variant "$variant")"
    local prog method; prog="${spec%% *}"; method="${spec##* }"
    [ -z "$prog" ] && return 0
    [ "$prog" = "afalg_bench" ]   && [ "$have_afalg"   = 0 ] && return 0
    [ "$prog" = "openssl_bench" ] && [ "$have_openssl" = 0 ] && return 0

    local type; type="$(type_for_alg "$alg")"
    # hashes have no encrypt/decrypt; normalise op for the row/skip dec
    if [ "$type" = "hash" ] && [ "$op" = "dec" ]; then return 0; fi

    local alignflag; [ "$align" = "unaligned" ] && alignflag="--unaligned" || alignflag="--aligned"

    local -a cmd=("$BIN/$prog" --alg "$alg" --type "$type" --op "$op"
                  --size "$size" $alignflag --threads "$thr"
                  --iters "$ITERS" --warmup "$WARMUP" --keybits "$kb"
                  --variant "$variant" --csv)
    # afalg_bench picks sendmsg/splice; openssl ignores method.
    if [ "$prog" = "afalg_bench" ]; then cmd+=(--method "$method"); fi
    if [ -n "$PIN_CPU" ]; then cmd=(taskset -c "$PIN_CPU" "${cmd[@]}"); fi

    local perf_file row cyc ins cmiss llc cpus cpb bytes
    perf_file="$(mktemp)"

    if [ "$use_perf" = 1 ]; then
        row="$(perf stat -x, -e "$PERF_EVENTS" -o "$perf_file" -- "${cmd[@]}" 2>/dev/null)"
    else
        row="$("${cmd[@]}" 2>/dev/null)"
    fi
    local rc=$?
    if [ $rc -ne 0 ] || [ -z "$row" ]; then
        echo "  skip (rc=$rc): $variant $alg $size $align t$thr $op" >&2
        rm -f "$perf_file"
        return 0
    fi

    cyc=""; ins=""; cmiss=""; llc=""; cpus=""
    if [ "$use_perf" = 1 ] && [ -s "$perf_file" ]; then
        cyc="$(awk   -F, '$3=="cycles"{print $1}'          "$perf_file" | tr -d ' ')"
        ins="$(awk   -F, '$3=="instructions"{print $1}'    "$perf_file" | tr -d ' ')"
        cmiss="$(awk -F, '$3=="cache-misses"{print $1}'    "$perf_file" | tr -d ' ')"
        llc="$(awk   -F, '$3=="LLC-load-misses"{print $1}' "$perf_file" | tr -d ' ')"
        cpus="$(awk  -F, '/seconds time elapsed/{print $1}' "$perf_file" | tr -d ' ')"
    fi
    rm -f "$perf_file"

    # cycles-per-byte = cycles / (size * iters * threads)
    cpb=""
    if [ -n "$cyc" ]; then
        bytes=$(( size * ITERS * thr ))
        cpb="$(awk -v c="$cyc" -v b="$bytes" 'BEGIN{ if(b>0) printf "%.4f", c/b; }')"
    fi

    echo "${row},${rep},${cyc},${ins},${cmiss},${llc},${cpus},${cpb}" >> "$OUT"
    echo "  ok: $variant $alg sz=$size $align t$thr $op rep=$rep  cpb=${cpb:-NA}" >&2
}

echo "=== matrix on kernel $KREL -> $OUT ===" >&2
for variant in $VARIANTS; do
  for alg in $ALGS; do
    for size in $SIZES; do
      for align in $ALIGNS; do
        for thr in $THREADS; do
          for op in $OPS; do
            for kb in $KEYBITS; do
              for rep in $(seq 1 "$REPEATS"); do
                run_one "$variant" "$alg" "$size" "$align" "$thr" "$op" "$kb" "$rep"
              done
            done
          done
        done
      done
    done
  done
done

echo "=== done. $(($(wc -l < "$OUT") - 1)) data rows in $OUT ===" >&2
