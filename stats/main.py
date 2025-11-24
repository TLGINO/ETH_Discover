#!/usr/bin/env python3
"""
Analyze transaction data from mempool vs on-chain state.
Uses multithreading for faster analysis.
Outputs full DataFrame with all transaction data for offline analysis.
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List, Tuple
from dataclasses import dataclass
import pandas as pd
from web3 import Web3
import sys
from collections import defaultdict
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import time
import pickle
import hashlib


@dataclass
class TransactionMetrics:
    tx_hash: str
    tx_hex: str
    tx_type: int
    first_seen: datetime
    status: str  # 'included', 'dropped', 'pending'
    block_number: int = None
    block_timestamp: int = None
    time_in_pool_seconds: float = None
    from_addr: str = None
    to_addr: str = None
    value: str = None
    gas: int = None
    gas_price: str = None


class TransactionAnalyzer:
    def __init__(
        self,
        db_path: str,
        alchemy_api_key: str,
        num_workers: int = 10,
        use_cache: bool = True,
    ):
        """
        Initialize the analyzer with database and Alchemy API key.

        Args:
            db_path: Path to SQLite database
            alchemy_api_key: Alchemy API key for Ethereum mainnet
            num_workers: Number of worker threads
            use_cache: Use cached transaction results
        """
        self.db_path = db_path
        self.num_workers = num_workers
        self.use_cache = use_cache
        self.results_lock = Lock()
        self.cache_file = ".tx_cache.pkl"
        self.cache_index_file = ".tx_cache_index.json"

        # Alchemy RPC endpoint
        rpc_url = f"https://eth-mainnet.g.alchemy.com/v2/{alchemy_api_key}"
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

        if not self.w3.is_connected():
            raise ConnectionError(f"Failed to connect to Alchemy")

        print(f"✓ Connected to Alchemy")
        print(f"✓ Chain ID: {self.w3.eth.chain_id}")
        print(f"✓ Latest Block: {self.w3.eth.block_number}")
        print(f"✓ Using {num_workers} worker threads")
        if use_cache:
            print(f"✓ Cache enabled: {self.cache_file}")

    def get_cache_hash(self, tx_hex: str) -> str:
        """Generate cache key from tx hex."""
        return hashlib.md5(tx_hex.encode()).hexdigest()

    def load_cache(self) -> Dict:
        """Load transaction cache from disk."""
        if not self.use_cache or not os.path.exists(self.cache_file):
            return {}

        try:
            with open(self.cache_file, "rb") as f:
                cache = pickle.load(f)
            print(f"✓ Loaded cache with {len(cache)} transactions")
            return cache
        except Exception as e:
            print(f"⚠ Error loading cache: {e}")
            return {}

    def save_cache(self, cache: Dict):
        """Save transaction cache to disk."""
        if not self.use_cache:
            return

        try:
            with open(self.cache_file, "wb") as f:
                pickle.dump(cache, f)
            print(f"✓ Saved cache with {len(cache)} transactions")
        except Exception as e:
            print(f"⚠ Error saving cache: {e}")

    def get_transactions_from_db(self) -> List[Tuple[str, datetime, str, str, str]]:
        """Fetch all transactions from database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get transactions from TRANSACTIONS_RELAYED (these are the ones we relayed)
        cursor.execute(
            """
            SELECT tx, timestamp, client_ip, client_id, node_id FROM TRANSACTIONS
            ORDER BY timestamp ASC
        """
        )

        transactions = []
        for row in cursor.fetchall():
            tx_data = row["tx"]
            timestamp = datetime.fromisoformat(row["timestamp"])
            client_ip = row["client_ip"]
            client_id = row["client_id"]
            node_id = row["node_id"]
            transactions.append((tx_data, timestamp, client_ip, client_id, node_id))

        conn.close()
        return transactions

    def parse_transaction_details(self, tx_hex: str) -> Dict:
        """
        Parse raw transaction data and extract details.

        Returns:
            Dict with transaction details
        """
        try:
            # Remove '0x' prefix if present
            if tx_hex.startswith("0x"):
                tx_hex = tx_hex[2:]

            # Decode transaction
            tx_bytes = bytes.fromhex(tx_hex)

            # Determine transaction type from first byte
            if tx_bytes[0] == 0x01:
                tx_type = 1
            elif tx_bytes[0] == 0x02:
                tx_type = 2
            else:
                tx_type = 0  # Legacy

            # Parse basic structure (simplified - only gets basic fields)
            # For full parsing, we'd need a transaction decoder
            result = {
                "type": tx_type,
                "from": None,
                "to": None,
                "value": None,
                "gas": None,
                "gas_price": None,
            }

            # Try to get details from chain if tx is included
            try:
                tx_hash = self.w3.keccak(hexstr=tx_hex)
                tx_hash_hex = tx_hash.hex()

                tx = self.w3.eth.get_transaction(tx_hash_hex)
                if tx:
                    result["from"] = tx.get("from")
                    result["to"] = tx.get("to")
                    result["value"] = str(tx.get("value", 0))
                    result["gas"] = tx.get("gas")
                    result["gasPrice"] = str(tx.get("gasPrice", 0))
            except Exception:
                pass

            return result
        except Exception as e:
            return {
                "type": None,
                "from": None,
                "to": None,
                "value": None,
                "gas": None,
                "gas_price": None,
            }

    def get_transaction_status(self, tx_hex: str) -> Tuple[str, int, int]:
        """
        Check if transaction is on-chain.

        Returns:
            Tuple of (status, block_number, block_timestamp)
            status: 'included', 'dropped', 'pending'
        """
        try:
            # Calculate tx hash from raw data
            tx_hash = self.w3.keccak(hexstr=tx_hex)
            tx_hash_hex = tx_hash.hex()

            try:
                receipt = self.w3.eth.get_transaction_receipt(tx_hash_hex)
                if receipt:
                    block_number = receipt["blockNumber"]
                    block = self.w3.eth.get_block(block_number)
                    return "included", block_number, block["timestamp"]
            except Exception:
                pass

            # Check if transaction is in pending pool
            try:
                pending_tx = self.w3.eth.get_transaction(tx_hash_hex)
                if pending_tx:
                    return "pending", None, None
            except Exception:
                pass

            # Not found anywhere = dropped/evicted
            return "dropped", None, None

        except Exception as e:
            return "unknown", None, None

    def process_transaction(
        self,
        tx_data: str,
        first_seen: datetime,
        current_time: datetime,
        cache: Dict,
        client_ip: str,
        client_id: str,
        node_id: str,
    ) -> TransactionMetrics:
        """
        Process a single transaction (worker thread function).
        """
        cache_key = self.get_cache_hash(tx_data)

        # Check cache first
        if cache_key in cache:
            cached = cache[cache_key]
            return cached

        status, block_number, block_timestamp = self.get_transaction_status(tx_data)
        parsed = self.parse_transaction_details(tx_data)
        tx_type = parsed["type"]

        # Calculate time in pool
        if status == "included" and block_timestamp:
            time_in_pool = block_timestamp - first_seen.timestamp()
        elif status == "dropped":
            time_in_pool = (current_time - first_seen).total_seconds()
        else:  # pending
            time_in_pool = (current_time - first_seen).total_seconds()

        tx_hash = self.w3.keccak(hexstr=tx_data).hex()

        metrics = TransactionMetrics(
            tx_hash=tx_hash,
            tx_hex=tx_data,
            tx_type=tx_type,
            first_seen=first_seen,
            status=status,
            block_number=block_number,
            block_timestamp=block_timestamp,
            time_in_pool_seconds=time_in_pool,
            from_addr=parsed.get("from"),
            to_addr=parsed.get("to"),
            value=parsed.get("value"),
            gas=parsed.get("gas"),
            gas_price=parsed.get("gasPrice"),
        )

        # Cache result
        with self.results_lock:
            cache[cache_key] = metrics

        return metrics

    def calculate_metrics(self) -> Tuple[List[TransactionMetrics], Dict]:
        """
        Calculate all metrics using multithreading.

        Returns:
            Tuple of (metrics_list, summary_stats)
        """
        print("\n📊 Analyzing transactions...\n")

        # Load cache
        cache = self.load_cache() if self.use_cache else {}

        transactions = self.get_transactions_from_db()
        print(f"Found {len(transactions)} transactions in database\n")

        if not transactions:
            print("No transactions found in database!")
            return [], {}

        metrics_list: List[TransactionMetrics] = []

        current_time = datetime.utcnow()
        total_txs = len(transactions)
        processed = 0
        cached_count = 0
        start_time = time.time()

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_workers=self.num_workers) as executor:
            # Submit all tasks
            futures = {
                executor.submit(
                    self.process_transaction,
                    tx_data,
                    first_seen,
                    current_time,
                    cache,
                    client_ip,
                    client_id,
                    node_id,
                ): i
                for i, (
                    tx_data,
                    first_seen,
                    client_ip,
                    client_id,
                    node_id,
                ) in enumerate(transactions)
            }

            # Process completed tasks
            for future in as_completed(futures):
                try:
                    metrics = future.result()
                    metrics_list.append(metrics)

                    processed += 1

                    # Progress update every 10 transactions
                    if processed % 10 == 0:
                        elapsed = time.time() - start_time
                        rate = processed / elapsed if elapsed > 0 else 0
                        eta = (total_txs - processed) / rate if rate > 0 else 0
                        print(
                            f"Progress: {processed}/{total_txs} ({processed/total_txs*100:.1f}%) - {rate:.1f} tx/s - ETA: {eta:.0f}s"
                        )

                except Exception as e:
                    print(f"Error processing transaction: {e}")

        elapsed = time.time() - start_time
        print(
            f"\n✓ Processed {processed} transactions in {elapsed:.2f}s ({processed/elapsed:.1f} tx/s)\n"
        )

        # Save cache
        if self.use_cache:
            self.save_cache(cache)

        # Calculate summary stats
        status_count = defaultdict(int)
        tx_type_count = defaultdict(int)
        time_in_pool_list = []

        for m in metrics_list:
            status_count[m.status] += 1
            tx_type_count[m.tx_type] += 1
            time_in_pool_list.append(m.time_in_pool_seconds)

        dropped_count = status_count["dropped"]
        included_count = status_count["included"]
        pending_count = status_count["pending"]
        dropped_rate = (dropped_count / total_txs * 100) if total_txs > 0 else 0

        time_stats = {
            "min": min(time_in_pool_list) if time_in_pool_list else 0,
            "max": max(time_in_pool_list) if time_in_pool_list else 0,
            "avg": (
                sum(time_in_pool_list) / len(time_in_pool_list)
                if time_in_pool_list
                else 0
            ),
            "median": (
                sorted(time_in_pool_list)[len(time_in_pool_list) // 2]
                if time_in_pool_list
                else 0
            ),
        }

        tx_type_names = {
            0: "Legacy",
            1: "EIP-2930 (Access Lists)",
            2: "EIP-1559 (Dynamic Fees)",
            None: "Unknown",
        }

        summary = {
            "total_transactions": total_txs,
            "included": included_count,
            "dropped": dropped_count,
            "pending": pending_count,
            "dropped_rate_percentage": round(dropped_rate, 2),
            "time_stats": time_stats,
            "tx_types": {
                tx_type_names.get(k, f"Type {k}"): v for k, v in tx_type_count.items()
            },
        }

        return metrics_list, summary

    def metrics_to_dataframe(
        self, metrics_list: List[TransactionMetrics]
    ) -> pd.DataFrame:
        """Convert metrics list to DataFrame."""
        data = []
        for m in metrics_list:
            data.append(
                {
                    "tx_hash": m.tx_hash,
                    "tx_type": m.tx_type,
                    "tx_type_name": ["Legacy", "EIP-2930", "EIP-1559", "Unknown"][
                        min(m.tx_type or 3, 3)
                    ],
                    "first_seen_utc": m.first_seen.isoformat(),
                    "status": m.status,
                    "block_number": m.block_number,
                    "block_timestamp": m.block_timestamp,
                    "time_in_pool_seconds": m.time_in_pool_seconds,
                    "from_address": m.from_addr,
                    "to_address": m.to_addr,
                    "value_wei": m.value,
                    "gas": m.gas,
                    "gas_price_wei": m.gas_price,
                }
            )

        df = pd.DataFrame(data)
        return df

    @staticmethod
    def _format_seconds(seconds: float) -> str:
        """Convert seconds to human readable format."""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"

    def print_summary(self, summary: Dict):
        """Pretty print the summary stats."""
        if not summary:
            return

        print("\n" + "=" * 70)
        print("TRANSACTION ANALYSIS SUMMARY")
        print("=" * 70)

        print(f"\n📈 SUMMARY:")
        print(f"  Total Transactions:  {summary.get('total_transactions', 0)}")
        print(f"  ✓ Included:          {summary.get('included', 0)}")
        print(f"  ✗ Dropped:           {summary.get('dropped', 0)}")
        print(f"  ⏳ Pending:           {summary.get('pending', 0)}")

        print(f"\n🗑️  DROPPED/EVICTED RATE:")
        print(f"  Rate:                {summary.get('dropped_rate_percentage', 0)}%")

        types = summary.get("tx_types", {})
        print(f"\n📦 TRANSACTION TYPES:")
        for tx_type, count in types.items():
            percentage = count / summary.get("total_transactions", 1) * 100
            print(f"  {tx_type:.<40} {count} ({percentage:.1f}%)")

        time_stats = summary.get("time_stats", {})
        print(f"\n⏱️  TIME IN POOL:")
        print(
            f"  Minimum:             {self._format_seconds(time_stats.get('min', 0))} ({time_stats.get('min', 0)}s)"
        )
        print(
            f"  Maximum:             {self._format_seconds(time_stats.get('max', 0))} ({time_stats.get('max', 0)}s)"
        )
        print(
            f"  Average:             {self._format_seconds(time_stats.get('avg', 0))} ({time_stats.get('avg', 0)}s)"
        )
        print(
            f"  Median:              {self._format_seconds(time_stats.get('median', 0))} ({time_stats.get('median', 0)}s)"
        )

        print("\n" + "=" * 70 + "\n")


def main():
    """Main entry point."""
    # Configuration
    DB_PATH = "../tx_data.db"
    ALCHEMY_API_KEY = "hNDILvs5J8QZTv8t9KJx_LK_AE7hgFR6"
    NUM_WORKERS = 30
    USE_CACHE = True

    if not ALCHEMY_API_KEY:
        print("❌ Error: ALCHEMY_API_KEY environment variable not set")
        print("Set it with: export ALCHEMY_API_KEY='your_api_key'")
        sys.exit(1)

    # Override with command line arguments if provided
    if len(sys.argv) > 1:
        ALCHEMY_API_KEY = sys.argv[1]
    if len(sys.argv) > 2:
        DB_PATH = sys.argv[2]
    if len(sys.argv) > 3:
        NUM_WORKERS = int(sys.argv[3])
    if len(sys.argv) > 4:
        USE_CACHE = sys.argv[4].lower() == "true"

    print(f"🔧 Configuration:")
    print(f"  Database:      {DB_PATH}")
    print(f"  Alchemy API:   {ALCHEMY_API_KEY[:10]}...")
    print(f"  Workers:       {NUM_WORKERS}")
    print(f"  Cache:         {USE_CACHE}\n")

    try:
        analyzer = TransactionAnalyzer(
            DB_PATH, ALCHEMY_API_KEY, num_workers=NUM_WORKERS, use_cache=USE_CACHE
        )
        metrics_list, summary = analyzer.calculate_metrics()
        analyzer.print_summary(summary)

        # Convert to DataFrame
        df = analyzer.metrics_to_dataframe(metrics_list)

        # Save DataFrame to CSV (for easy viewing and analysis)
        csv_file = (
            f"transaction_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        df.to_csv(csv_file, index=False)
        print(f"✓ Full dataset saved to: {csv_file}")

        # Also save as Parquet (more efficient for large datasets)
        parquet_file = (
            f"transaction_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.parquet"
        )
        df.to_parquet(parquet_file, index=False)
        print(f"✓ Full dataset saved to: {parquet_file}")

        print(f"\n📊 DataFrame shape: {df.shape}")
        print(f"\nDataFrame columns:")
        print(df.dtypes)
        print(f"\nFirst 5 rows:")
        print(df.head())

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
