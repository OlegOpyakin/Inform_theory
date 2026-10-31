#!/bin/bash
# ============================================================
# AF_ALG zero-copy removal — full benchmark (one kernel)
# Pause: 10 s between cells (not between repeats)
# perf stat: only on LAST 2 repeats of each cell
# Cache cleanup (fstrim + drop_caches): after each phase,
#   and after fio cells with bs=256k/1M (VM + optional host)
# Run twice: pre-fix kernel (6.14.1) and post-fix (7.2.11)
# STEP 1a checks every timed path's output against OpenSSL first
# fio: qd=1 on sync engine (afalg.so), qd>1 on async (afalg_async.so);
#   FIO_ASYNC=0 forces the sync engine everywhere
# ============================================================
set -u

PAUSE=10
RESULTS=results
mkdir -p "$RESULTS"
KVER=$(uname -r)
STAMP=$(date +%Y%m%d_%H%M%S)
LOG="$RESULTS/bench_${KVER}_${STAMP}.log"

HOST_SSH="${HOST_SSH:-}"

exec > >(tee -a "$LOG") 2>&1
log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
pause() { log "pause ${PAUSE}s"; sleep "$PAUSE"; }

# ------------------------------------------------------------
# Socket limits AF_ALG needs for payloads up to 16 MiB (alg_core warns if not):
#   wmem_max   — SO_SNDBUF; below the payload, sendmsg deadlocks in
#                af_alg_wait_for_wmem
#   rmem_max   — SO_RCVBUF; below the payload, AEAD output gets split
#   optmem_max — AF_ALG scatterlists are charged here; ~16 MiB sendmsg needs
#                more than the 128 KiB default (ENOMEM). Per netns on >= 6.9.
# ------------------------------------------------------------
for kv in net.core.wmem_max=67108864 net.core.wmem_default=67108864 \
          net.core.rmem_max=67108864 net.core.optmem_max=1048576; do
    k=${kv%%=*}; v=${kv#*=}
    if [ "$(sysctl -n "$k")" -lt "$v" ]; then
        log "raising $k to $v"
        sudo sysctl -w "$kv" >/dev/null
    fi
done

# ------------------------------------------------------------
# Cache/TRIM cleanup
# ------------------------------------------------------------
cleanup_vm() {
  log "cleanup VM: sync + fstrim -a + drop_caches"
  sudo sync
  sudo fstrim -a 2>/dev/null || log "fstrim -a failed (no discard support?)"
  echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
  log "VM caches dropped"
}

cleanup_host() {
  if [ -z "$HOST_SSH" ]; then
    log "host cleanup skipped (HOST_SSH not set)"
    return
  fi
  log "cleanup HOST via $HOST_SSH"
  ssh -o BatchMode=yes -o ConnectTimeout=5 "$HOST_SSH" \
      "sync && fstrim -a 2>/dev/null; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null" \
      >> "$LOG" 2>&1 || log "WARN: host cleanup failed"
}

cleanup_all() { cleanup_vm; cleanup_host; }

PERF_EVENTS="cycles,instructions,cache-misses,LLC-load-misses,context-switches,cpu-migrations,page-faults,branch-misses,dTLB-load-misses,L1-dcache-load-misses"

log "============================================================"
log "AF_ALG benchmark START  kernel=$KVER  log=$LOG"
log "HOST_SSH='${HOST_SSH}' (empty = host cleanup disabled)"
log "============================================================"

# ============================================================
# 0. BUILD
# ============================================================
log "STEP 0: build"
make all
make fio-engine FIO_SRC=$PWD/fio-3.35 || log "WARN: fio-engine build failed (continue)"

# binary pre-check
for b in bin/afalg_bench bin/openssl_bench; do
    [ -x "$b" ] || { log "FATAL: $b missing or not executable"; exit 1; }
done
if [ ! -f bin/afalg.so ]; then
    log "WARN: bin/afalg.so missing — STEP 5 (fio) will be skipped"
    SKIP_FIO=1
else
    SKIP_FIO=0
fi
# qd>1 fio cells need the async engine: the sync one (FIO_SYNCIO) caps iodepth at 1.
# FIO_ASYNC=0 runs every cell on the sync engine (old behaviour; qd8 == qd1).
FIO_ASYNC="${FIO_ASYNC:-1}"
if [ "$FIO_ASYNC" = 1 ] && [ ! -f bin/afalg_async.so ]; then
    log "WARN: bin/afalg_async.so missing — fio cells with iodepth>1 will be skipped"
fi

# ============================================================
# 0a. ENVIRONMENT
# ============================================================
log "STEP 0a: environment"
{
  echo "--- uname ---"; uname -a
  echo "--- lscpu ---"; lscpu
  echo "--- siblings ---"
  for c in $(seq 0 7); do
    echo -n "cpu$c siblings: "
    cat /sys/devices/system/cpu/cpu$c/topology/thread_siblings_list 2>/dev/null || echo "n/a"
  done
  echo "--- crypto flags ---"
  grep -o -E 'aes|avx|avx2|avx512f|vaes|sse4_2|pclmulqdq' /proc/cpuinfo | sort -u | tr '\n' ' '; echo
  echo "--- governor ---"
  cpupower frequency-info 2>/dev/null | grep -E 'governor|current policy' || echo "cpupower n/a"
  echo "--- af_alg_restrict ---"
  cat /proc/sys/crypto/af_alg_restrict 2>/dev/null || echo "not present (ok for <7.3)"
  echo "--- wmem_max ---"
  sysctl net.core.wmem_max net.core.wmem_default 2>/dev/null
  echo "--- cbc(aes) driver ---"
  grep -A2 'name.*: cbc(aes)' /proc/crypto 2>/dev/null | grep -E 'name|driver|priority'
}
if [ -f /proc/sys/crypto/af_alg_restrict ]; then
  echo 0 | sudo tee /proc/sys/crypto/af_alg_restrict
fi

# ============================================================
# 1. ALGORITHMS PRESENT
# ============================================================
log "STEP 1: /proc/crypto"
grep -E 'cbc\(aes\)|gcm\(aes\)|sha256' /proc/crypto

# ============================================================
# 1a. CORRECTNESS: every timed path vs an OpenSSL reference (untimed)
# ============================================================
log "STEP 1a: verify outputs against OpenSSL"
VERIFY_FAIL=0
for SZ in 4k 64k 1M 16M; do
  for AL in --aligned --unaligned; do
    for M in sendmsg splice; do
      for SPEC in "--alg cbc(aes) --op enc" "--alg cbc(aes) --op dec" "--type hash --alg sha256"; do
        # shellcheck disable=SC2086
        if ! ./bin/afalg_bench $SPEC --method $M --size $SZ $AL --iters 1 --warmup 0 --verify >/dev/null; then
          log "WARN: verify FAILED: afalg_bench $SPEC --method $M --size $SZ $AL"
          VERIFY_FAIL=1
        fi
      done
    done
  done
  if ! ./bin/afalg_bench --alg 'cbc(aes)' --file-backed --size $SZ --iters 1 --warmup 0 --verify >/dev/null; then
    log "WARN: verify FAILED: afalg_bench --file-backed --size $SZ"
    VERIFY_FAIL=1
  fi
  for SPEC in "--alg cbc(aes)" "--type hash --alg sha256"; do
    # shellcheck disable=SC2086
    ./bin/openssl_bench $SPEC --size $SZ --iters 1 --warmup 0 --verify >/dev/null \
      || { log "WARN: verify FAILED: openssl_bench $SPEC --size $SZ"; VERIFY_FAIL=1; }
  done
done
log "verify: $([ "$VERIFY_FAIL" = 0 ] && echo 'all OK' || echo 'FAILURES above — check before trusting results')"

# ============================================================
# 2. CONFIRM KERNEL NATURE -> kernel_has_zc
# ============================================================
log "STEP 2: confirm kernel nature"
SPLICE=$(./bin/afalg_bench --alg 'cbc(aes)' --method splice  --size 64k --aligned --iters 20000 --csv)
SENDMSG=$(./bin/afalg_bench --alg 'cbc(aes)' --method sendmsg --size 64k --aligned --iters 20000 --csv)
echo "$SPLICE"  > "$RESULTS/nature_splice_${KVER}.csv"
echo "$SENDMSG" > "$RESULTS/nature_sendmsg_${KVER}.csv"
log "splice : $SPLICE"
log "sendmsg: $SENDMSG"

# threshold 1.01 (was 1.2): pre-fix ratio is ~1.03, post-fix ~0.97
{
  header=$(./bin/afalg_bench --alg 'cbc(aes)' --method splice --size 64k --aligned --header 2>/dev/null | head -1)
  tp_idx=$(echo "$header" | tr ',' '\n' | grep -niE 'throughput|mib|mb/s|mbps|gbit' | head -1 | cut -d: -f1)
  if [ -z "$tp_idx" ]; then
    log "WARN: cannot auto-detect throughput column; kernel_has_zc=unknown"
    echo "${KVER},unknown" > "$RESULTS/kernel_has_zc_${KVER}.txt"
  else
    s_tp=$(echo "$SPLICE"  | awk -F, -v i="$tp_idx" '{print $i}')
    m_tp=$(echo "$SENDMSG" | awk -F, -v i="$tp_idx" '{print $i}')
    ratio=$(awk -v s="$s_tp" -v m="$m_tp" 'BEGIN{ if(m>0) printf "%.3f", s/m; else print "0" }')
    zc=$(awk -v s="$s_tp" -v m="$m_tp" 'BEGIN{ if(m>0 && s/m>1.01) print 1; else print 0 }')
    log "kernel_has_zc=$zc (splice/sendmsg throughput ratio=$ratio, col=$tp_idx, threshold=1.01)"
    echo "${KVER},${zc}" > "$RESULTS/kernel_has_zc_${KVER}.txt"
  fi
}
cleanup_all

# ============================================================
# 3. AF_ALG MATRIX
# ============================================================
log "STEP 3a: afalg matrix (small sizes)"
sudo GOVERNOR=1 PIN_CPU=2 PAUSE=$PAUSE PERF_LAST_N=2 PERF_EVENTS="$PERF_EVENTS" \
  ITERS=50000 REPEATS=10 SIZES="64 256 1024 4096 16384 65536" \
  scripts/run_matrix.sh
cleanup_all

log "STEP 3b: afalg matrix (large sizes)"
sudo GOVERNOR=1 PIN_CPU=2 PAUSE=$PAUSE PERF_LAST_N=2 PERF_EVENTS="$PERF_EVENTS" \
  ITERS=2000  REPEATS=10 SIZES="262144 1048576 4194304 16777216" \
  scripts/run_matrix.sh
cleanup_all

# ============================================================
# 4. OPENSSL REFERENCE (10 reps, perf on 9-10)
# ============================================================
log "STEP 4: openssl reference"
# the benches print header-less rows; give the file its header once
[ -s "$RESULTS/openssl_${KVER}.csv" ] || ./bin/openssl_bench --header > "$RESULTS/openssl_${KVER}.csv"
for SZ in 512 4096 16384 65536; do
  for REP in $(seq 1 10); do
    if [ "$REP" -ge 9 ]; then
      log "openssl sz=$SZ rep=$REP (WITH perf)"
      sudo perf stat -e "$PERF_EVENTS" \
        -o "$RESULTS/perf_openssl_${SZ}_${REP}_${KVER}.txt" \
        ./bin/openssl_bench --alg 'cbc(aes)' --size $SZ --aligned --iters 20000 --csv \
          >> "$RESULTS/openssl_${KVER}.csv"
    else
      log "openssl sz=$SZ rep=$REP"
      ./bin/openssl_bench --alg 'cbc(aes)' --size $SZ --aligned --iters 20000 --csv \
        >> "$RESULTS/openssl_${KVER}.csv"
    fi
  done
  pause
done
cleanup_all

# ============================================================
# 5. FIO MATRIX (5 reps, perf on 4-5)
# ============================================================
if [ "$SKIP_FIO" = "1" ]; then
  log "STEP 5: fio matrix — SKIPPED (bin/afalg.so missing)"
else
  log "STEP 5: fio matrix"
  for BS in 512 4k 16k 64k 256k 1M; do
    for NJ in 1 4; do
      for IOD in 1 8; do
        # iodepth 1 -> sync engine; >1 -> async engine (real in-flight ops).
        if [ "$IOD" -gt 1 ] && [ "$FIO_ASYNC" = 1 ]; then
          [ -f bin/afalg_async.so ] || { log "skip qd=$IOD cells (no bin/afalg_async.so)"; continue; }
          ENG=async; ENGINE_SO=bin/afalg_async.so
        else
          ENG=sync;  ENGINE_SO=bin/afalg.so
        fi
        for METH in sendmsg splice; do
          for RW in write read; do
            CELL="bs=${BS}_nj=${NJ}_qd=${IOD}_${ENG}_${METH}_${RW}"
            log "fio cell START: $CELL"
            for REP in $(seq 1 5); do
              OUT="$RESULTS/fio_${ENG}_${METH}_${BS}_nj${NJ}_qd${IOD}_${RW}_${REP}_${KVER}.json"
              if [ "$REP" -ge 4 ]; then
                log "  rep=$REP (WITH perf)"
                PERF_OUT="$RESULTS/perf_${ENG}_${METH}_${BS}_nj${NJ}_qd${IOD}_${RW}_${REP}_${KVER}.txt"
                if ! sudo perf stat -e "$PERF_EVENTS" -o "$PERF_OUT" \
                     fio --ioengine=external:./$ENGINE_SO --name=enc --rw=$RW \
                         --afalg_alg='cbc(aes)' --afalg_type=skcipher \
                         --afalg_method=$METH --afalg_keybits=128 \
                         --bs=$BS --size=256m --numjobs=$NJ --iodepth=$IOD \
                         --output-format=json --output=$OUT; then
                  log "WARN: fio failed: $CELL rep=$REP"
                fi
              else
                log "  rep=$REP"
                if ! fio --ioengine=external:./$ENGINE_SO --name=enc --rw=$RW \
                      --afalg_alg='cbc(aes)' --afalg_type=skcipher \
                      --afalg_method=$METH --afalg_keybits=128 \
                      --bs=$BS --size=256m --numjobs=$NJ --iodepth=$IOD \
                      --output-format=json --output=$OUT; then
                  log "WARN: fio failed: $CELL rep=$REP"
                fi
              fi
            done
            log "fio cell END:   $CELL"
            pause
            if [ "$BS" = "256k" ] || [ "$BS" = "1M" ]; then
              cleanup_all
            fi
          done
        done
      done
    done
  done
fi
cleanup_all

# ============================================================
# 6. ANALYZE
# ============================================================
log "STEP 6: analyze"
python3 scripts/plot_results.py "$RESULTS"/results_*.csv \
  -o figures --summary "$RESULTS/summary.csv" || log "WARN: plot_results failed"

log "============================================================"
log "AF_ALG benchmark DONE  kernel=$KVER  log=$LOG"
log "============================================================"
