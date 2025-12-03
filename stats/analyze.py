#!/usr/bin/env python3
"""
Enhanced transaction analysis (one plot per PNG) with:
- Value and gas price histograms (ALL and INCLUDED)
- Mempool duration histogram (INCLUDED)
- Gas price vs mempool time scatter (INCLUDED)
- Block coverage distribution (x: coverage %, y: % of blocks)
- Coverage vs block size scatter
- Per-block coverage plot (x: block number, y: coverage %)

Each plot includes mean, median, and total count annotations.

The 'Transaction Inclusion Rate Over Time (from first_seen)' plot has been removed.

If you cannot connect to a node, you can provide a local JSON file with block totals:
  --block-totals /path/to/block_totals.json
Format:
{
  "19761234": {"total_txs": 224, "timestamp": 1732812345},
  "19761235": {"total_txs": 198, "timestamp": 1732812400}
}
"""

import argparse
import json
import pickle
import sys
import time
from pathlib import Path
from multiprocessing import Pool, cpu_count

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from rlp import decode
from web3 import Web3

# Pick a style if available
preferred_styles = ["seaborn", "ggplot", "classic"]
for style in preferred_styles:
    if style in plt.style.available:
        plt.style.use(style)
        break


def decode_tx_hex(tx_hex):
    """Decode transaction hex with EIP-2718 type prefix support."""
    try:
        if isinstance(tx_hex, str):
            if tx_hex.startswith("0x"):
                tx_hex = tx_hex[2:]
            tx_bytes = bytes.fromhex(tx_hex)
        else:
            tx_bytes = tx_hex

        if len(tx_bytes) > 0:
            first_byte = tx_bytes[0]

            if first_byte == 0x01:
                decoded = decode(tx_bytes[1:])
                if len(decoded) == 11:
                    value = int.from_bytes(decoded[5], "big")
                    gas_price = int.from_bytes(decoded[2], "big")
                    return value, gas_price, "OK_EIP2930"

            elif first_byte == 0x02:
                decoded = decode(tx_bytes[1:])
                if len(decoded) == 12:
                    value = int.from_bytes(decoded[6], "big")
                    gas_price = int.from_bytes(decoded[3], "big")
                    return value, gas_price, "OK_EIP1559"

            elif first_byte >= 0xC0:
                decoded = decode(tx_bytes)
                if len(decoded) == 9:
                    value = int.from_bytes(decoded[4], "big")
                    gas_price = int.from_bytes(decoded[1], "big")
                    return value, gas_price, "OK_LEGACY"

        return None, None, "UNRECOGNIZED_FORMAT"
    except Exception:
        return None, None, "ERROR"


def save_histogram(series, xlabel, title, out_path, log_y=True, bins=100, unit_div=1):
    """Save a histogram for a pandas Series (numeric) with mean, median, and count."""
    series = pd.Series(series).dropna()
    if series.empty:
        print(f"⚠ Skipping {title}: no data")
        return
    
    # Calculate statistics
    data_converted = series / unit_div
    mean_val = data_converted.mean()
    median_val = data_converted.median()
    count_val = len(data_converted)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(data_converted, bins=bins, color="#4C72B0", alpha=0.8, edgecolor="black")
    ax.set_xlabel(xlabel, fontsize=12)
    ax.set_ylabel("Frequency", fontsize=12)
    ax.set_title(title, fontsize=14, fontweight="bold")
    if log_y:
        ax.set_yscale("log")
    ax.grid(alpha=0.3)
    
    # Add statistics text box
    stats_text = f"Mean: {mean_val:.4f}\nMedian: {median_val:.4f}\nCount: {count_val:,}"
    ax.text(0.98, 0.97, stats_text, transform=ax.transAxes, 
            fontsize=10, verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"✓ Saved {out_path}")


def save_scatter(x, y, c, xlabel, ylabel, title, out_path, xlog=False, ylog=False, cmap="viridis"):
    """Save scatter plot where c is color (can be None) with mean, median, and count."""
    if len(x) == 0:
        print(f"⚠ Skipping {title}: no data")
        return
    
    # Calculate statistics
    x_arr = np.array(x)
    y_arr = np.array(y)
    mean_x = np.mean(x_arr)
    median_x = np.median(x_arr)
    mean_y = np.mean(y_arr)
    median_y = np.median(y_arr)
    count_val = len(x_arr)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    sc = ax.scatter(x, y, c=c if c is not None else "C0", cmap=cmap, alpha=0.5, s=10, linewidth=0)
    ax.set_xlabel(xlabel, fontsize=12)
    ax.set_ylabel(ylabel, fontsize=12)
    ax.set_title(title, fontsize=14, fontweight="bold")
    if xlog:
        ax.set_xscale("log")
    if ylog:
        ax.set_yscale("log")
    if c is not None:
        cbar = plt.colorbar(sc, ax=ax)
        cbar.set_label("Value (ETH)", fontsize=10)
    ax.grid(alpha=0.3)
    
    # Add statistics text box
    stats_text = f"X Mean: {mean_x:.4f} | Median: {median_x:.4f}\nY Mean: {mean_y:.4f} | Median: {median_y:.4f}\nCount: {count_val:,}"
    ax.text(0.98, 0.97, stats_text, transform=ax.transAxes, 
            fontsize=9, verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"✓ Saved {out_path}")


def save_block_coverage_hist(coverage_pct_series, out_path, bins=50):
    """
    Block coverage histogram:
    - x axis: coverage percentage bins (0..100)
    - y axis: percentage of blocks in each bin
    """
    series = pd.Series(coverage_pct_series).dropna()
    if series.empty:
        print("⚠ Skipping block coverage histogram: no data")
        return
    
    # Calculate statistics
    mean_val = series.mean()
    median_val = series.median()
    count_val = len(series)
    
    counts, bin_edges = np.histogram(series, bins=bins, range=(0, 100))
    total = counts.sum()
    pct = (counts / total * 100.0) if total > 0 else np.zeros_like(counts, dtype=float)
    centers = (bin_edges[:-1] + bin_edges[1:]) / 2.0
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.bar(centers, pct, width=(bin_edges[1] - bin_edges[0]) * 0.9, color="#E24A33", edgecolor="black", alpha=0.8)
    ax.set_xlabel("Coverage Percentage (%)", fontsize=12)
    ax.set_ylabel("Percent of Blocks (%)", fontsize=12)
    ax.set_title("Block Coverage Distribution (percent of blocks per coverage bin)", fontsize=14, fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    
    # Add statistics text box
    stats_text = f"Mean: {mean_val:.2f}%\nMedian: {median_val:.2f}%\nCount: {count_val:,}"
    ax.text(0.98, 0.97, stats_text, transform=ax.transAxes, 
            fontsize=10, verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"✓ Saved {out_path}")


def plot_block_coverage_by_blocknum(coverage_df, out_path, rolling_window=None):
    """
    Per-block coverage (% found per block):
    - x axis: block number
    - y axis: coverage_pct
    """
    if coverage_df.empty:
        print("⚠ Skipping per-block coverage plot: no data")
        return
    df = coverage_df.copy()
    # Ensure block_number is a column
    if "block_number" not in df.columns:
        df = df.reset_index()
        if "index" in df.columns:
            df.rename(columns={"index": "block_number"}, inplace=True)
    df["block_number"] = pd.to_numeric(df["block_number"], errors="coerce")
    df = df.dropna(subset=["block_number", "coverage_pct"])
    df = df.sort_values("block_number")
    if df.empty:
        print("⚠ No usable rows for per-block coverage after cleaning")
        return

    x = df["block_number"].values
    y = df["coverage_pct"].values
    
    # Calculate statistics
    mean_val = np.mean(y)
    median_val = np.median(y)
    count_val = len(y)

    fig, ax = plt.subplots(figsize=(14, 6))
    ax.scatter(x, y, s=8, alpha=0.6, color="#2E86AB", edgecolors="none", label="Per-block coverage")
    # Rolling mean to denoise
    n = len(df)
    if rolling_window is None:
        rolling_window = max(5, min(max(5, n // 100), 1001))
    y_roll = pd.Series(y, index=df["block_number"]).rolling(window=rolling_window, min_periods=1, center=True).mean()
    ax.plot(y_roll.index.values, y_roll.values, color="#E24A33", linewidth=2, label=f"{rolling_window}-block rolling mean")

    ax.set_xlabel("Block Number", fontsize=12)
    ax.set_ylabel("Coverage (%)", fontsize=12)
    ax.set_title("Per-Block Coverage (% of transactions found per block)", fontsize=14, fontweight="bold")
    ax.grid(alpha=0.3)
    ax.legend(loc='upper left')
    
    # Add statistics text box
    stats_text = f"Mean: {mean_val:.2f}%\nMedian: {median_val:.2f}%\nCount: {count_val:,}"
    ax.text(0.98, 0.97, stats_text, transform=ax.transAxes, 
            fontsize=10, verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    fig.tight_layout()
    fig.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"✓ Saved {out_path}")


def load_block_cache(cache_path: Path) -> dict:
    """Load block cache dict from pickle if exists, otherwise return empty dict."""
    if cache_path.exists():
        try:
            with cache_path.open("rb") as f:
                cache = pickle.load(f)
            if isinstance(cache, dict):
                print(f"✓ Loaded block cache ({len(cache):,} entries) from {cache_path}")
                return cache
        except Exception:
            pass
    return {}


def save_block_cache(cache: dict, cache_path: Path, previous_size: int) -> int:
    """Save block cache dict to pickle only if size changed.Returns new size."""
    size = len(cache)
    if size == previous_size:
        return previous_size
    try:
        tmp = cache_path.with_suffix(cache_path.suffix + ".tmp")
        with tmp.open("wb") as f:
            pickle.dump(cache, f)
        tmp.replace(cache_path)
        print(f"✓ Wrote block cache ({size:,} entries) to {cache_path}")
    except Exception as e:
        print(f"⚠ Failed saving block cache: {e}")
    return size


def analyze_transactions(parquet_file: str, node_url: str = None, block_totals_json: str = None):
    """Main analysis function."""
    parquet_path = Path(parquet_file)
    print(f"📖 Loading {parquet_path}...")
    df = pd.read_parquet(parquet_path)
    print(f"✓ Loaded {len(df):,} transactions")

    # dedupe tx_hex
    dup_tx_hex = df["tx_hex"].duplicated().sum()
    if dup_tx_hex > 0:
        print(f"🔎 Removing {dup_tx_hex:,} duplicate tx_hex entries...")
        df = df.drop_duplicates(subset=["tx_hex"], keep="first")
        print(f"✓ Remaining: {len(df):,} transactions")

    # decode transactions (parallel)
    print("🔍 Decoding transactions (parallel)...")
    num_workers = max(1, cpu_count() - 1)
    with Pool(num_workers) as pool:
        results = pool.map(decode_tx_hex, df["tx_hex"].values, chunksize=1000)
    values_list, fees_list, errors_list = zip(*results)
    df["value_decoded"] = values_list
    df["gas_price_decoded"] = fees_list
    df["decode_status"] = errors_list
    successful = (df["decode_status"].str.startswith("OK")).sum()
    print(f"✓ Decoded {successful:,} / {len(df):,} transactions (successful)")

    # basic counts
    total = len(df)
    included = (df["status"] == "included").sum()
    dropped = (df["status"] == "dropped").sum()
    print(f"Total: {total:,}  Included: {included:,}  Dropped: {dropped:,}")

    # Prepare series
    all_values = df["value_decoded"].dropna()
    all_fees = df["gas_price_decoded"].dropna()
    included_df = df[df["status"] == "included"].copy()
    inc_values = included_df["value_decoded"].dropna()
    inc_fees = included_df["gas_price_decoded"].dropna()

    stem = parquet_path.stem

    # Save individual plots (one per PNG)
    save_histogram(all_values, "Value (ETH)", "ALL Transaction Values", f"{stem}_all_values.png", unit_div=1e18)
    save_histogram(inc_values, "Value (ETH)", "INCLUDED Transaction Values", f"{stem}_included_values.png", unit_div=1e18)
    save_histogram(all_fees, "Gas Price (Gwei)", "ALL Gas Prices", f"{stem}_all_gas_prices.png", unit_div=1e9)
    save_histogram(inc_fees, "Gas Price (Gwei)", "INCLUDED Gas Prices", f"{stem}_included_gas_prices.png", unit_div=1e9)

    # Mempool time histogram (included only)
    if "time_in_pool_seconds" in included_df.columns:
        mempool_times = included_df["time_in_pool_seconds"].dropna()
        save_histogram(mempool_times, "Time in Mempool (seconds)", "Mempool Duration (included txs)", f"{stem}_mempool_time.png", unit_div=1, log_y=True)
    else:
        print("⚠ No time_in_pool_seconds column; skipping mempool time plot")

    # Gas price vs mempool time scatter (included only)
    included_with_data = included_df[
        included_df["gas_price_decoded"].notna()
        & included_df["time_in_pool_seconds"].notna()
        & included_df["value_decoded"].notna()
    ]
    save_scatter(
        included_with_data["gas_price_decoded"].values / 1e9,
        included_with_data["time_in_pool_seconds"].values,
        included_with_data["value_decoded"].values / 1e18,
        "Gas Price (Gwei)",
        "Time in Mempool (seconds)",
        "Gas Price vs Mempool Time (included txs)",
        f"{stem}_gas_vs_mempool_time.png",
        xlog=True,
        ylog=True,
    )

    # BLOCK COVERAGE: metadata via node or local JSON
    included_df_with_block = included_df[included_df["block_number"].notna()].copy()
    if included_df_with_block.empty:
        print("⚠ No included transactions with block_number; skipping block coverage analysis")
        print("✓ All done")
        return

    included_df_with_block["block_number"] = included_df_with_block["block_number"].astype(int)
    block_nums = np.unique(included_df_with_block["block_number"].values)
    print(f"🔗 Preparing block coverage for {len(block_nums):,} blocks ...")

    # Load cache
    cache_path = parquet_path.with_name(f"{stem}_block_cache.pkl")
    block_cache = load_block_cache(cache_path)
    cache_size = len(block_cache)

    # Optionally load local block totals JSON
    if block_totals_json:
        try:
            with open(block_totals_json, "r") as f:
                local_totals = json.load(f)
            # Merge into cache
            for k, v in local_totals.items():
                bn_int = int(k)
                block_cache.setdefault(bn_int, {})
                if "total_txs" in v:
                    block_cache[bn_int]["total_txs"] = int(v["total_txs"])
                if "timestamp" in v:
                    block_cache[bn_int]["timestamp"] = int(v["timestamp"])
            cache_size = save_block_cache(block_cache, cache_path, cache_size)
            print(f"✓ Merged local block totals from {block_totals_json}")
        except Exception as e:
            print(f"⚠ Failed to read --block-totals JSON: {e}")

    # Connect to node if provided and needed
    w3 = None
    if node_url:
        try:
            w3 = Web3(Web3.HTTPProvider(node_url))
            if not w3.is_connected():
                print("⚠ Could not connect to node; will use cache/local totals only")
                w3 = None
            else:
                print("✓ Connected to node")
        except Exception as e:
            print(f"⚠ Web3 init failed: {e} — using cache/local totals only")
            w3 = None

    # Build coverage dict
    block_coverage = {}
    save_every = 200
    for i, bn in enumerate(block_nums):
        if (i + 1) % 1000 == 0:
            print(f"  Prepared {i+1:,}/{len(block_nums):,} blocks")
        bn_int = int(bn)

        # First from cache/local totals
        total_txs_in_block = None
        timestamp = None
        if bn_int in block_cache:
            total_txs_in_block = block_cache[bn_int].get("total_txs")
            timestamp = block_cache[bn_int].get("timestamp")

        # If missing, try node
        if (total_txs_in_block is None or timestamp is None) and w3:
            try:
                block = w3.eth.get_block(bn_int)
                total_txs_in_block = len(block["transactions"])
                timestamp = int(block["timestamp"])
                block_cache[bn_int] = {"total_txs": total_txs_in_block, "timestamp": timestamp}
                cache_size = save_block_cache(block_cache, cache_path, cache_size)
            except Exception:
                pass

        our_txs_in_block = int((included_df_with_block["block_number"] == bn_int).sum())
        coverage_pct = (our_txs_in_block / total_txs_in_block * 100.0) if total_txs_in_block and total_txs_in_block > 0 else np.nan

        if total_txs_in_block is not None:
            block_coverage[bn_int] = {
                "block_number": bn_int,
                "total_txs": total_txs_in_block,
                "our_txs": our_txs_in_block,
                "coverage_pct": coverage_pct,
                "timestamp": timestamp,
            }

    coverage_df = pd.DataFrame.from_dict(block_coverage, orient="index")

    if coverage_df.empty:
        print("❌ Block coverage cannot be computed: no block metadata (total_txs).")
        print("Provide a working node URL or a --block-totals JSON file.")
        print("✓ All done")
        return

    # 1) Block coverage distribution (x: coverage %, y: % of blocks)
    save_block_coverage_hist(coverage_df["coverage_pct"], f"{stem}_block_coverage_pct_hist.png")

    # 2) Coverage vs block size scatter
    cov_size_x = coverage_df["total_txs"].values
    cov_size_y = coverage_df["coverage_pct"].values
    
    # Calculate statistics
    mean_x = np.mean(cov_size_x)
    median_x = np.median(cov_size_x)
    mean_y = np.mean(cov_size_y)
    median_y = np.median(cov_size_y)
    count_val = len(cov_size_x)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    ax.scatter(cov_size_x, cov_size_y, alpha=0.6, s=20, color="#2E86AB", edgecolors="black", linewidth=0.4)
    ax.set_xlabel("Total Transactions in Block", fontsize=12)
    ax.set_ylabel("Our Coverage (%)", fontsize=12)
    ax.set_title("Coverage vs Block Size", fontsize=14, fontweight="bold")
    ax.grid(alpha=0.3)
    
    # Add statistics text box
    stats_text = f"X Mean: {mean_x:.2f} | Median: {median_x:.2f}\nY Mean: {mean_y:.2f}% | Median: {median_y:.2f}%\nCount: {count_val:,}"
    ax.text(0.98, 0.97, stats_text, transform=ax.transAxes, 
            fontsize=9, verticalalignment='top', horizontalalignment='right',
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8))
    
    fig.tight_layout()
    out_cov_size = f"{stem}_coverage_vs_size.png"
    fig.savefig(out_cov_size, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"✓ Saved {out_cov_size}")

    # 3) Per-block coverage with X axis as block number (requested)
    plot_block_coverage_by_blocknum(coverage_df, f"{stem}_coverage_by_blocknum.png")

    print("✓ All done")


def parse_args():
    p = argparse.ArgumentParser(description="Analyze Ethereum transactions and block coverage.")
    p.add_argument("parquet_file", help="Path to parquet file with transactions")
    p.add_argument("node_url", nargs="?", help="Ethereum RPC URL, e.g.http://localhost:8545")
    p.add_argument("--block-totals", default=None, help="Path to JSON file with total txs per block")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    analyze_transactions(args.parquet_file, args.node_url, args.block_totals)