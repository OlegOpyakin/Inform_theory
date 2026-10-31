#!/usr/bin/env bash
#
# run_matrix.sh — Layer 3 orchestration (patched).
# Patches vs original:
#   + PAUSE env: sleep N seconds between cells (not between repeats)
#   + PERF_LAST_N env: wrap only last N repeats with perf stat (0 = all, old behaviour)
#   + PERF_EVENTS env: extend beyond base 4 events; extras get extra CSV columns
#   + VARIANTS may include afalg-zc-file (splice from a page-cache file,
#     afalg_bench --file-backed: the path the zero-copy removal targets)
#   + VERIFY env: 1 = pass --verify (output checked against OpenSSL before timing;
#     a mismatch makes the bench exit non-zero and the cell is skipped)
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BIN="$ROOT/bin"
RESULTS_DIR="$ROOT/results"
KREL="$(uname -r)"
OUT="$RESULTS_DIR/results_${KREL}.csv"

# ---- defaults ----
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
PAUSE="${PAUSE:-0}"
PERF_LAST_N="${PERF_LAST_N:-0}"
VERIFY="${VERIFY:-0}"
PERF_EVENTS="${PERF_EVENTS:-cycles,instructions,cache-misses,LLC-load-misses}"

mkdir -p "$RESULTS_DIR"

# ---- split perf events: base 4 -> named columns, rest -> extra columns ----
BASE_EVENTS="cycles,instructions,cache-misses,LLC-load-misses"
EXTRA_EVENTS=""
EXTRA_HEADER=""
IFS=',' read -ra _perf_events <<< "$PERF_EVENTS"
for e in "${_perf_events[@]}"; do
    e="$(echo "$e" | xargs)"
    case ",$BASE_EVENTS," in
        *",$e,"*) ;;
        *) EXTRA_EVENTS="${EXTRA_EVENTS:+$EXTRA_EVENTS,}$e" ;;
    esac
done
unset _perf_events

col_name() {
    case "$1" in
        cycles) echo "cycles" ;;
        instructions) echo "instructions" ;;
        cache-misses) echo "cache_misses" ;;
        LLC-load-misses) echo "llc_load_misses" ;;
        context-switches) echo "context_switches" ;;
        cpu-migrations) echo "cpu_migrations" ;;
        page-faults) echo "page_faults" ;;
        branch-misses) echo "branch_misses" ;;
        dTLB-load-misses) echo "dtlb_load_misses" ;;
        L1-dcache-load-misses) echo "l1_dcache_load_misses" ;;
        *) echo "$1" | tr 'A-Z-' 'a-z_' ;;
    esac
}

if [ -n "$EXTRA_EVENTS" ]; then
    IFS=',' read -ra _extra <<< "$EXTRA_EVENTS"
    for e in "${_extra[@]}"; do
        EXTRA_HEADER="${EXTRA_HEADER},$(col_name "$e")"
    done
    unset _extra
fi

CLEAN_REPS=$(( REPEATS - PERF_LAST_N ))
[ "$CLEAN_REPS" -lt 0 ] && CLEAN_REPS=0

echo "perf events: base=[$BASE_EVENTS] extra=[${EXTRA_EVENTS:-none}]" >&2

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

# ---- governor ----
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

# ---- CSV header ----
BENCH_HEADER="$("$BIN/afalg_bench" --header 2>/dev/null || "$BIN/openssl_bench" --header)"
CSV_HEADER="${BENCH_HEADER},repeat,cycles,instructions,cache_misses,llc_load_misses,cpu_seconds,cycles_per_byte${EXTRA_HEADER}"
if [ ! -f "$OUT" ]; then
    echo "$CSV_HEADER" > "$OUT"
    echo "created $OUT" >&2
elif [ "$(head -n1 "$OUT")" != "$CSV_HEADER" ]; then
    # Different columns (other PERF_EVENTS, or an older bench schema): appending
    # would shift values under the wrong names.
    echo "error: $OUT has a different header than this run would write." >&2
    echo "  existing: $(head -n1 "$OUT")" >&2
    echo "  this run: $CSV_HEADER" >&2
    echo "  move it aside or use the same PERF_EVENTS." >&2
    exit 1
else
    echo "appending to existing $OUT" >&2
fi

bin_for_variant() {
    case "$1" in
        afalg-copy)       echo "afalg_bench sendmsg" ;;
        afalg-zc)         echo "afalg_bench splice" ;;
        afalg-zc-file)    echo "afalg_bench file" ;;
        userspace-aesni)  echo "openssl_bench evp" ;;
        *) echo "" ;;
    esac
}

type_for_alg() {
    case "$1" in
        sha*|md5|hmac*) echo "hash" ;;
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
    if [ "$type" = "hash" ] && [ "$op" = "dec" ]; then return 0; fi

    local alignflag; [ "$align" = "unaligned" ] && alignflag="--unaligned" || alignflag="--aligned"

    local -a cmd=("$BIN/$prog" --alg "$alg" --type "$type" --op "$op"
                  --size "$size" $alignflag --threads "$thr"
                  --iters "$ITERS" --warmup "$WARMUP" --keybits "$kb"
                  --variant "$variant" --csv)
    if [ "$prog" = "afalg_bench" ]; then
        if [ "$method" = file ]; then cmd+=(--file-backed); else cmd+=(--method "$method"); fi
    fi
    if [ "$VERIFY" = 1 ]; then cmd+=(--verify); fi
    if [ -n "$PIN_CPU" ]; then cmd=(taskset -c "$PIN_CPU" "${cmd[@]}"); fi

    local perf_file row cyc ins cmiss llc cpus cpb bytes extra_vals
    perf_file="$(mktemp)"

    # perf only on last PERF_LAST_N repeats (0 = old behaviour: every repeat)
    local use_perf_now=0
    if [ "$use_perf" = 1 ]; then
        if [ "$PERF_LAST_N" = 0 ]; then
            use_perf_now=1
        elif [ "$rep" -gt "$CLEAN_REPS" ]; then
            use_perf_now=1
        fi
    fi

    if [ "$use_perf_now" = 1 ]; then
        row="$(perf stat -x, -e "$PERF_EVENTS" -o "$perf_file" -- "${cmd[@]}" 2>/dev/null)"
    else
        row="$("${cmd[@]}" 2>/dev/null)"
    fi
    local rc=$?
    if [ $rc -ne 0 ] || [ -z "$row" ]; then
        echo "  skip (rc=$rc): $variant $alg $size $align t$thr $op rep=$rep" >&2
        rm -f "$perf_file"
        return 0
    fi

    cyc=""; ins=""; cmiss=""; llc=""; cpus=""; extra_vals=""
    if [ "$use_perf_now" = 1 ] && [ -s "$perf_file" ]; then
        cyc="$(awk   -F, '$3=="cycles"          && $1 ~ /^[0-9.]+$/{print $1; exit}' "$perf_file" | tr -d ' ')"
        ins="$(awk   -F, '$3=="instructions"    && $1 ~ /^[0-9.]+$/{print $1; exit}' "$perf_file" | tr -d ' ')"
        cmiss="$(awk -F, '$3=="cache-misses"    && $1 ~ /^[0-9.]+$/{print $1; exit}' "$perf_file" | tr -d ' ')"
        llc="$(awk   -F, '$3=="LLC-load-misses" && $1 ~ /^[0-9.]+$/{print $1; exit}' "$perf_file" | tr -d ' ')"
        cpus="$(awk  -F, '/seconds time elapsed/{print $1; exit}' "$perf_file" | tr -d ' ')"

        if [ -n "$EXTRA_EVENTS" ]; then
            IFS=',' read -ra _extra <<< "$EXTRA_EVENTS"
            for e in "${_extra[@]}"; do
                v="$(awk -F, -v ev="$e" '$3==ev && $1 ~ /^[0-9.]+$/{print $1; exit}' "$perf_file" | tr -d ' ')"
                extra_vals="${extra_vals},${v}"
            done
            unset _extra
        fi
    fi
    rm -f "$perf_file"

    # perf counts the whole process, so divide by every op it ran: warmup +
    # timed iters (+1 for --verify). Dividing by ITERS alone inflates cpb by
    # WARMUP/ITERS (e.g. +50% at ITERS=2000 WARMUP=1000). Setup cost remains.
    cpb=""
    if [ -n "$cyc" ]; then
        local ops=$(( ITERS + WARMUP ))
        [ "$VERIFY" = 1 ] && ops=$(( ops + 1 ))
        bytes=$(( size * ops * thr ))
        cpb="$(awk -v c="$cyc" -v b="$bytes" 'BEGIN{ if(b>0) printf "%.4f", c/b; }')"
    fi

    echo "${row},${rep},${cyc},${ins},${cmiss},${llc},${cpus},${cpb}${extra_vals}" >> "$OUT"
    local ptag=""
    [ "$use_perf_now" = 1 ] && ptag=" [perf]"
    echo "  ok: $variant $alg sz=$size $align t$thr $op rep=$rep$ptag  cpb=${cpb:-NA}" >&2
}

echo "=== matrix on kernel $KREL -> $OUT (repeats=$REPEATS, clean=$CLEAN_REPS, perf_last=$PERF_LAST_N) ===" >&2
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
              if [ "$PAUSE" -gt 0 ]; then
                echo "  pause ${PAUSE}s" >&2
                sleep "$PAUSE"
              fi
            done
          done
        done
      done
    done
  done
done

echo "=== done. $(($(wc -l < "$OUT") - 1)) data rows in $OUT ===" >&2
