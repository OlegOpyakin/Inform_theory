#!/usr/bin/env python3
"""
plot_results.py — parse results CSVs and plot throughput / latency /
cycles-per-byte against message size, tying the picture back to H1–H4.

Reads one or more results_*.csv files (the schema written by run_matrix.sh),
aggregates repeats into mean + 95% CI, writes an aggregated summary CSV, and
renders PNGs (one chart per alg x alignment x threads x metric), with a series
per (variant, kernel) so the two-kernel comparison shows up directly.

Usage:
    scripts/plot_results.py results/results_*.csv
    scripts/plot_results.py results/results_6.8.csv -o figures/ --summary agg.csv

Only the plotting step needs matplotlib; aggregation/summary work without it.
"""
import argparse
import csv
import glob
import math
import os
import sys
from collections import defaultdict

NUMERIC = ("bytes", "threads", "throughput_MBps",
           "lat_p50_us", "lat_p99_us", "cycles_per_byte")


def load_rows(paths):
    rows = []
    for p in paths:
        with open(p, newline="") as f:
            for r in csv.DictReader(f):
                rows.append(r)
    return rows


def to_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# Two-sided 95% Student t quantiles by degrees of freedom. With the 3-10
# repeats per cell used here, the normal 1.96 understates the CI by 15-130%.
T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
       8: 2.306, 9: 2.262, 10: 2.228, 12: 2.179, 15: 2.131, 20: 2.086,
       30: 2.042, 60: 2.000}


def t95(df):
    """t quantile for df, conservatively rounding df down to the table."""
    if df >= 120:
        return 1.96
    return T95[max(k for k in T95 if k <= df)]


def mean_ci(vals):
    """Return (mean, half-width of 95% CI) using the Student t distribution."""
    vals = [v for v in vals if v is not None]
    n = len(vals)
    if n == 0:
        return None, None
    m = sum(vals) / n
    if n < 2:
        return m, 0.0
    var = sum((v - m) ** 2 for v in vals) / (n - 1)
    sd = math.sqrt(var)
    return m, t95(n - 1) * sd / math.sqrt(n)


# A "cell" is one matrix point; repeats collapse into it. keybits is "" in CSVs
# written before that column existed.
CELL_KEYS = ("variant", "kernel", "alg", "keybits", "type", "op", "alignment",
             "threads", "bytes")
METRICS = ("throughput_MBps", "lat_p50_us", "lat_p99_us", "cycles_per_byte")


def aggregate(rows):
    buckets = defaultdict(lambda: defaultdict(list))
    for r in rows:
        key = tuple(r.get(k, "") for k in CELL_KEYS)
        for m in METRICS:
            buckets[key][m].append(to_float(r.get(m)))
    agg = {}
    for key, metricvals in buckets.items():
        d = dict(zip(CELL_KEYS, key))
        for m in METRICS:
            mean, ci = mean_ci(metricvals[m])
            d[m + "_mean"] = mean
            d[m + "_ci"] = ci
        d["n"] = len(metricvals[METRICS[0]])
        agg[key] = d
    return agg


def write_summary(agg, path):
    cols = list(CELL_KEYS) + ["n"]
    for m in METRICS:
        cols += [m + "_mean", m + "_ci"]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for d in sorted(agg.values(), key=lambda x: (x["alg"], x["keybits"], x["alignment"],
                                                      x["threads"], x["variant"],
                                                      x["kernel"],
                                                      to_float(x["bytes"]) or 0)):
            w.writerow({c: d.get(c, "") for c in cols})
    print(f"wrote summary: {path} ({len(agg)} cells)")


def human_bytes(n):
    n = int(n)
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return f"{n}{unit}"
        n //= 1024
    return f"{n}T"


METRIC_LABEL = {
    "throughput_MBps": ("Throughput (MB/s)", True),   # (ylabel, log-y)
    "lat_p99_us": ("Latency p99 (us)", True),
    "lat_p50_us": ("Latency p50 (us)", True),
    "cycles_per_byte": ("Cycles per byte", True),
}


def plot(agg, outdir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plots "
              "(summary CSV still written). pip install matplotlib", file=sys.stderr)
        return

    os.makedirs(outdir, exist_ok=True)
    cells = list(agg.values())

    # Group charts by (alg, keybits, alignment, threads, op) x metric.
    groups = defaultdict(list)
    for d in cells:
        groups[(d["alg"], d["keybits"], d["alignment"], d["threads"], d["op"])].append(d)

    made = 0
    for (alg, kb, align, thr, op), ds in groups.items():
        kbtag = f"_k{kb}" if kb not in ("", "0") else ""
        for metric in METRICS:
            ylabel, logy = METRIC_LABEL[metric]
            # series keyed by (variant, kernel)
            series = defaultdict(list)
            for d in ds:
                y = d[metric + "_mean"]
                if y is None:
                    continue
                x = to_float(d["bytes"])
                series[(d["variant"], d["kernel"])].append(
                    (x, y, d[metric + "_ci"] or 0.0))
            if not series:
                continue
            fig, ax = plt.subplots(figsize=(8, 5))
            for (variant, kernel), pts in sorted(series.items()):
                pts.sort(key=lambda t: t[0])
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                es = [p[2] for p in pts]
                label = f"{variant} [{kernel}]"
                ax.errorbar(xs, ys, yerr=es, marker="o", capsize=3, label=label)
            ax.set_xscale("log", base=2)
            if logy:
                ax.set_yscale("log")
            ax.set_xlabel("Message size (bytes)")
            ax.set_ylabel(ylabel)
            ax.set_title(f"{alg}{' ' + kb + '-bit' if kbtag else ''}  {align}  threads={thr}  op={op}")
            ax.grid(True, which="both", ls=":", alpha=0.5)
            ax.legend(fontsize=8)
            safe_alg = alg.replace("(", "_").replace(")", "")
            fname = f"{safe_alg}{kbtag}_{align}_t{thr}_{op}_{metric}.png"
            fig.tight_layout()
            fig.savefig(os.path.join(outdir, fname), dpi=120)
            plt.close(fig)
            made += 1
    print(f"wrote {made} charts to {outdir}/")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="+", help="results CSV file(s); globs allowed")
    ap.add_argument("-o", "--outdir", default="figures", help="output dir for PNGs")
    ap.add_argument("--summary", default=None, help="write aggregated summary CSV here")
    args = ap.parse_args()

    paths = []
    for c in args.csv:
        paths.extend(glob.glob(c) or [c])
    paths = [p for p in paths if os.path.exists(p)]
    if not paths:
        print("no input CSV files found", file=sys.stderr)
        return 1

    rows = load_rows(paths)
    print(f"loaded {len(rows)} rows from {len(paths)} file(s)")
    agg = aggregate(rows)
    if args.summary:
        write_summary(agg, args.summary)
    plot(agg, args.outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
