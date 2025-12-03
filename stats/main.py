#!/usr/bin/env python3
"""
Ultra-fast transaction analyzer with streaming disk writes. 
Writes results incrementally during processing to avoid memory bottlenecks. 
Target: 500+ tx/s with minimal memory usage.
"""

import sqlite3
import asyncio
import aiohttp
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
import pandas as pd
import sys
from collections import defaultdict
import os
from threading import Lock, Thread, Event
import time
import pickle
import hashlib
import pyarrow as pa
import pyarrow.parquet as pq
import logging

logging.basicConfig(level=logging.WARNING)

@dataclass
class TransactionMetrics:
    tx_hash: str
    tx_hex: str
    tx_type: int
    first_seen: str  # Keep as ISO format string
    status: str
    block_number: Optional[int] = None
    block_timestamp: Optional[int] = None
    time_in_pool_seconds: float = 0
    from_addr: Optional[str] = None
    to_addr: Optional[str] = None
    value: str = "0"
    gas: Optional[int] = None
    gas_price: str = "0"


class StreamingWriter:
    """Handle streaming writes to CSV and Parquet without buffering all data."""
    
    def __init__(self, csv_file: str, parquet_file: str, batch_size: int = 10000):
        self.csv_file = csv_file
        self.parquet_file = parquet_file
        self.batch_size = batch_size
        self.csv_written = False
        self.parquet_writer = None
        self.write_lock = Lock()
        self.batch_buffer = []
        self.total_written = 0
        
        # Initialize Parquet writer with schema - all strings for flexibility
        self.schema = pa.schema([
            ('tx_hash', pa.string()),
            ('tx_hex', pa.string()),
            ('tx_type', pa.int32()),
            ('first_seen', pa.string()),  # Keep as string
            ('status', pa.string()),
            ('block_number', pa.int64()),
            ('block_timestamp', pa.int64()),
            ('time_in_pool_seconds', pa.float64()),
            ('from_addr', pa.string()),
            ('to_addr', pa.string()),
            ('value', pa.string()),
            ('gas', pa.int64()),
            ('gas_price', pa.string()),
        ])

    def write_batch(self, metrics_list: List[TransactionMetrics], final: bool = False):
        """Write a batch of metrics to disk efficiently."""
        if not metrics_list and not final:
            return

        with self.write_lock:
            # Add to buffer
            self.batch_buffer.extend(metrics_list)

            # Write when buffer reaches batch size or on final call
            if len(self.batch_buffer) >= self.batch_size or (final and self.batch_buffer):
                self._flush_buffer()

    def _flush_buffer(self):
        """Flush buffer to both CSV and Parquet."""
        if not self.batch_buffer:
            return

        try:
            # Convert to list of dicts, ensuring all types are correct
            data = []
            for m in self.batch_buffer:
                row = asdict(m)
                # Ensure first_seen stays as string
                if isinstance(row['first_seen'], datetime):
                    row['first_seen'] = row['first_seen'].isoformat()
                else:
                    row['first_seen'] = str(row['first_seen'])
                data.append(row)
            
            # Create DataFrame with explicit dtypes to prevent auto-conversion
            df = pd.DataFrame(data)
            
            # Force string columns to stay as strings
            df['first_seen'] = df['first_seen'].astype(str)
            df['tx_hash'] = df['tx_hash'].astype(str)
            df['tx_hex'] = df['tx_hex'].astype(str)
            df['status'] = df['status'].astype(str)
            df['from_addr'] = df['from_addr'].astype(str)
            df['to_addr'] = df['to_addr'].astype(str)
            df['value'] = df['value'].astype(str)
            df['gas_price'] = df['gas_price'].astype(str)

            # Write to CSV (append mode)
            if self.csv_written:
                df.to_csv(self.csv_file, mode='a', header=False, index=False)
            else:
                df.to_csv(self.csv_file, mode='w', header=True, index=False)
                self.csv_written = True

            # Write to Parquet (append to table)
            if self.parquet_writer is None:
                self.parquet_writer = pq.ParquetWriter(
                    self.parquet_file,
                    self.schema,
                    compression='snappy'
                )

            # Convert to PyArrow table with explicit type casting
            try:
                table = pa.table({
                    'tx_hash': pa.array(df['tx_hash'].values, type=pa.string()),
                    'tx_hex': pa.array(df['tx_hex'].values, type=pa.string()),
                    'tx_type': pa.array(df['tx_type'].values, type=pa.int32()),
                    'first_seen': pa.array(df['first_seen'].values, type=pa.string()),
                    'status': pa.array(df['status'].values, type=pa.string()),
                    'block_number': pa.array(df['block_number'].values, type=pa.int64()),
                    'block_timestamp': pa.array(df['block_timestamp'].values, type=pa.int64()),
                    'time_in_pool_seconds': pa.array(df['time_in_pool_seconds'].values, type=pa.float64()),
                    'from_addr': pa.array(df['from_addr'].values, type=pa.string()),
                    'to_addr': pa.array(df['to_addr'].values, type=pa.string()),
                    'value': pa.array(df['value'].values, type=pa.string()),
                    'gas': pa.array(df['gas'].values, type=pa.int64()),
                    'gas_price': pa.array(df['gas_price'].values, type=pa.string()),
                })
                self.parquet_writer.write_table(table)
            except Exception as e:
                print(f"⚠ PyArrow conversion error: {e}, trying pandas conversion")
                # Fallback to pandas conversion
                table = pa.Table.from_pandas(df, schema=self.schema)
                self.parquet_writer.write_table(table)

            self.total_written += len(self.batch_buffer)
            print(f"💾 Written {self.total_written:,} transactions to disk")

            self.batch_buffer.clear()

        except Exception as e:
            print(f"⚠ Write error: {e}")
            import traceback
            traceback.print_exc()

    def finalize(self):
        """Finalize writes and close files."""
        self._flush_buffer()
        if self.parquet_writer:
            self.parquet_writer.close()
        print(f"✓ Finalized disk writes: {self.total_written:,} transactions")


class FastTransactionAnalyzer:
    def __init__(
        self,
        db_path: str,
        node_url: str = "http://localhost:8545",
        num_workers: int = 50,
        use_cache: bool = True,
        cache_write_interval: int = 30,
        batch_size: int = 500,
        rpc_batch_size: int = 100,
        write_batch_size: int = 10000,
    ):
        """
        Initialize fast analyzer with streaming writes. 

        Args:
            db_path: Path to SQLite database
            node_url: Local Ethereum node RPC URL
            num_workers: Number of async workers
            use_cache: Use cached transaction results
            cache_write_interval: Seconds between cache writes
            batch_size: Transactions per processing batch
            rpc_batch_size: Transactions per RPC batch call
            write_batch_size: Transactions before flushing to disk
        """
        self.db_path = db_path
        self.node_url = node_url
        self.num_workers = num_workers
        self.use_cache = use_cache
        self.cache_write_interval = cache_write_interval
        self.batch_size = batch_size
        self.rpc_batch_size = rpc_batch_size
        self.write_batch_size = write_batch_size
        
        self.cache_file = ".tx_cache.pkl"
        self.results_lock = Lock()
        self.block_cache = {}
        self.block_cache_lock = Lock()
        
        # Background cache writer
        self.cache_writer_thread = None
        self.stop_cache_writer = Event()
        self.last_cache_size = 0
        
        # Streaming writer
        self.writer = None
        
        print(f"🚀 High-Performance Streaming Transaction Analyzer")
        print(f"✓ Async workers: {num_workers}")
        print(f"✓ Processing batch size: {batch_size}")
        print(f"✓ RPC batch size: {rpc_batch_size}")
        print(f"✓ Write batch size: {write_batch_size}")
        print(f"✓ Cache enabled: {use_cache}")

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

    def save_cache(self, cache: Dict, periodic: bool = False):
        """Save transaction cache to disk."""
        if not self.use_cache:
            return

        try:
            with self.results_lock:
                with open(self.cache_file, "wb") as f:
                    pickle.dump(cache, f)
                
                cache_size = len(cache)
                if periodic and cache_size > self.last_cache_size:
                    print(f"💾 Cache: {cache_size} txs")
                    self.last_cache_size = cache_size
                elif not periodic:
                    print(f"✓ Final cache: {cache_size} transactions")
        except Exception as e:
            print(f"⚠ Error saving cache: {e}")

    def start_cache_writer(self, cache: Dict):
        """Start background cache writer."""
        if not self.use_cache:
            return

        self.stop_cache_writer.clear()
        self.cache_writer_thread = Thread(
            target=self._cache_writer_worker, args=(cache,), daemon=True
        )
        self.cache_writer_thread.start()

    def stop_cache_writer_thread(self):
        """Stop cache writer thread."""
        if self.cache_writer_thread and self.cache_writer_thread.is_alive():
            self.stop_cache_writer.set()
            self.cache_writer_thread.join(timeout=5)

    def _cache_writer_worker(self, cache: Dict):
        """Background cache writer."""
        while not self.stop_cache_writer.is_set():
            try:
                if self.stop_cache_writer.wait(timeout=self.cache_write_interval):
                    break
                self.save_cache(cache, periodic=True)
            except Exception as e:
                print(f"⚠ Cache writer error: {e}")

    def get_transactions_from_db(self) -> List[Tuple]:
        """Fetch all transactions from database."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT tx, timestamp, client_ip, client_id, node_id FROM TRANSACTIONS ORDER BY timestamp ASC"
        )

        transactions = []
        for row in cursor.fetchall():
            transactions.append((
                row["tx"],
                row["timestamp"],
                row["client_ip"],
                row["client_id"],
                row["node_id"],
            ))

        conn.close()
        return transactions

    @staticmethod
    def parse_tx_type(tx_hex: str) -> int:
        """Extract transaction type from raw hex."""
        try:
            if tx_hex.startswith("0x"):
                tx_hex = tx_hex[2:]
            if len(tx_hex) < 2:
                return 0
            
            first_byte = int(tx_hex[:2], 16)
            if first_byte == 0x01:
                return 1
            elif first_byte == 0x02:
                return 2
            return 0
        except Exception:
            return 0

    async def batch_get_receipts(
        self, session: aiohttp.ClientSession, tx_hashes: List[str]
    ) -> Dict[str, Optional[Dict]]:
        """Batch RPC call to get transaction receipts."""
        if not tx_hashes:
            return {}

        batch_requests = [
            {
                "jsonrpc": "2.0",
                "method": "eth_getTransactionReceipt",
                "params": [tx_hash],
                "id": i,
            }
            for i, tx_hash in enumerate(tx_hashes)
        ]

        try:
            async with session.post(
                self.node_url,
                json=batch_requests,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    results = await resp.json()
                    receipt_data = {}
                    for result in results:
                        if "result" in result and result["result"]:
                            receipt_data[result["result"]["transactionHash"]] = result["result"]
                    return receipt_data
        except Exception as e:
            print(f"⚠ Receipt batch error: {e}")
        
        return {}

    async def batch_get_blocks(
        self, session: aiohttp.ClientSession, block_numbers: List[int]
    ) -> Dict[int, Optional[Dict]]:
        """Batch RPC call to get block data."""
        if not block_numbers:
            return {}

        uncached = []
        for bn in block_numbers:
            if bn not in self.block_cache:
                uncached.append(bn)

        if not uncached:
            return {bn: self.block_cache.get(bn) for bn in block_numbers}

        batch_requests = [
            {
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params": [hex(bn), False],
                "id": i,
            }
            for i, bn in enumerate(uncached)
        ]

        block_data = {}
        try:
            async with session.post(
                self.node_url,
                json=batch_requests,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    results = await resp.json()
                    for result in results:
                        if "result" in result and result["result"]:
                            block_num = int(result["result"]["number"], 16)
                            block_data[block_num] = result["result"]
                            with self.block_cache_lock:
                                self.block_cache[block_num] = result["result"]
        except Exception as e:
            print(f"⚠ Block batch error: {e}")

        for bn in block_numbers:
            if bn in self.block_cache:
                block_data[bn] = self.block_cache[bn]

        return block_data

    async def process_batch(
        self,
        session: aiohttp.ClientSession,
        batch: List[Tuple],
        cache: Dict,
        current_time: float,
    ) -> List[TransactionMetrics]:
        """Process a batch of transactions asynchronously."""
        results = []
        
        tx_hex_list = [tx[0] for tx in batch]
        tx_hashes_hex = []
        tx_hex_to_index = {}
        
        for i, tx_hex in enumerate(tx_hex_list):
            cache_key = self.get_cache_hash(tx_hex)
            
            if cache_key in cache:
                results.append(cache[cache_key])
                continue
            
            if tx_hex.startswith("0x"):
                clean_hex = tx_hex[2:]
            else:
                clean_hex = tx_hex
            
            try:
                from Crypto.Hash import keccak
                k = keccak.new(digest_bits=256)
                k.update(bytes.fromhex(clean_hex))
                tx_hash = "0x" + k.hexdigest()
                tx_hashes_hex.append(tx_hash)
                tx_hex_to_index[tx_hash] = (i, tx_hex, cache_key)
            except Exception:
                continue

        if not tx_hashes_hex:
            return results

        receipts = await self.batch_get_receipts(session, tx_hashes_hex)
        
        block_numbers = set()
        for receipt in receipts.values():
            if receipt and "blockNumber" in receipt:
                block_numbers.add(int(receipt["blockNumber"], 16))

        blocks_data = await self.batch_get_blocks(session, list(block_numbers))

        for tx_hash, (orig_idx, tx_hex, cache_key) in tx_hex_to_index.items():
            tx_data = batch[orig_idx]
            first_seen_str = tx_data[1]
            
            try:
                first_seen_ts = datetime.fromisoformat(first_seen_str).timestamp()
            except Exception:
                first_seen_ts = current_time

            receipt = receipts.get(tx_hash)
            
            if receipt:
                block_number = int(receipt["blockNumber"], 16)
                block = blocks_data.get(block_number, {})
                block_timestamp = int(block.get("timestamp", "0x0"), 16) if block else None
                
                status = "included"
                if block_timestamp:
                    time_in_pool = block_timestamp - first_seen_ts
                else:
                    time_in_pool = current_time - first_seen_ts
            else:
                status = "dropped"
                time_in_pool = current_time - first_seen_ts
                block_number = None
                block_timestamp = None

            tx_type = self.parse_tx_type(tx_hex)

            metrics = TransactionMetrics(
                tx_hash=tx_hash,
                tx_hex=tx_hex,
                tx_type=tx_type,
                first_seen=first_seen_str,  # Keep as string
                status=status,
                block_number=block_number,
                block_timestamp=block_timestamp,
                time_in_pool_seconds=time_in_pool,
                from_addr=None,
                to_addr=None,
                value="0",
                gas=None,
                gas_price="0",
            )

            with self.results_lock:
                cache[cache_key] = metrics
            
            results.append(metrics)

        return results

    async def worker(
        self,
        session: aiohttp.ClientSession,
        queue: asyncio.Queue,
        cache: Dict,
        current_time: float,
        progress_lock: asyncio.Lock,
        processed_count: List[int],
        total_count: int,
        start_time: float,
    ):
        """Worker coroutine for processing batches and streaming writes."""
        while True:
            try:
                batch = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                break

            try:
                batch_results = await self.process_batch(session, batch, cache, current_time)
                
                # Stream write results instead of buffering
                self.writer.write_batch(batch_results, final=False)
                
                processed_count[0] += len(batch)
                
                if processed_count[0] % 5000 == 0:
                    async with progress_lock:
                        elapsed = time.time() - start_time
                        rate = processed_count[0] / elapsed if elapsed > 0 else 0
                        eta = (total_count - processed_count[0]) / rate if rate > 0 else 0
                        print(
                            f"Progress: {processed_count[0]:,}/{total_count:,} ({processed_count[0]/total_count*100:.1f}%) - {rate:.0f} tx/s - ETA: {eta:.0f}s"
                        )
            except Exception as e:
                print(f"⚠ Worker error: {e}")
            finally:
                queue.task_done()

    async def calculate_metrics_async(self) -> Dict:
        """Calculate metrics asynchronously with streaming writes."""
        print("\n📊 Analyzing transactions with streaming disk writes...\n")

        cache = self.load_cache() if self.use_cache else {}
        self.start_cache_writer(cache)

        transactions = self.get_transactions_from_db()
        total_txs = len(transactions)
        
        print(f"Found {total_txs:,} transactions in database")
        print(f"Processing with {self.num_workers} workers...\n")

        if not transactions:
            print("No transactions found!")
            self.stop_cache_writer_thread()
            return {}

        # Initialize streaming writer
        csv_file = f"transaction_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        parquet_file = f"transaction_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.parquet"
        self.writer = StreamingWriter(csv_file, parquet_file, self.write_batch_size)

        queue = asyncio.Queue()
        processed_count = [0]
        progress_lock = asyncio.Lock()
        start_time = time.time()
        current_time = time.time()

        # Fill queue with batches
        for i in range(0, len(transactions), self.batch_size):
            batch = transactions[i : i + self.batch_size]
            await queue.put(batch)

        # Create session with connection pooling
        connector = aiohttp.TCPConnector(
            limit=self.num_workers * 2,
            limit_per_host=self.num_workers,
            ttl_dns_cache=300,
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create workers
            workers = [
                asyncio.create_task(
                    self.worker(
                        session,
                        queue,
                        cache,
                        current_time,
                        progress_lock,
                        processed_count,
                        total_txs,
                        start_time,
                    )
                )
                for _ in range(self.num_workers)
            ]

            # Wait for queue to be processed
            await queue.join()

            # Cancel workers
            for worker in workers:
                worker.cancel()

            await asyncio.gather(*workers, return_exceptions=True)

        elapsed = time.time() - start_time
        rate = processed_count[0] / elapsed if elapsed > 0 else 0
        print(f"\n✓ Processed {processed_count[0]:,} transactions in {elapsed:.2f}s ({rate:.0f} tx/s)")

        # Finalize disk writes
        print("\n💿 Finalizing disk writes... (this may take a moment)")
        self.writer.finalize()

        self.stop_cache_writer_thread()
        if self.use_cache:
            self.save_cache(cache, periodic=False)

        # Calculate summary stats from cache
        print("\n📊 Calculating summary statistics...")
        status_count = defaultdict(int)
        tx_type_count = defaultdict(int)
        time_in_pool_list = []

        for metrics in cache.values():
            status_count[metrics.status] += 1
            tx_type_count[metrics.tx_type] += 1
            time_in_pool_list.append(metrics.time_in_pool_seconds)

        dropped_count = status_count["dropped"]
        included_count = status_count["included"]
        dropped_rate = (dropped_count / total_txs * 100) if total_txs > 0 else 0

        time_stats = {
            "min": min(time_in_pool_list) if time_in_pool_list else 0,
            "max": max(time_in_pool_list) if time_in_pool_list else 0,
            "avg": sum(time_in_pool_list) / len(time_in_pool_list) if time_in_pool_list else 0,
            "median": sorted(time_in_pool_list)[len(time_in_pool_list) // 2] if time_in_pool_list else 0,
        }

        summary = {
            "total_transactions": total_txs,
            "included": included_count,
            "dropped": dropped_count,
            "dropped_rate_percentage": round(dropped_rate, 2),
            "time_stats": time_stats,
            "tx_types": {
                0: tx_type_count.get(0, 0),
                1: tx_type_count.get(1, 0),
                2: tx_type_count.get(2, 0),
            },
            "processing_rate_tx_per_sec": round(rate, 2),
            "total_time_seconds": round(elapsed, 2),
            "csv_file": csv_file,
            "parquet_file": parquet_file,
        }

        return summary

    def print_summary(self, summary: Dict):
        """Print summary stats."""
        if not summary:
            return

        print("\n" + "=" * 70)
        print("TRANSACTION ANALYSIS SUMMARY")
        print("=" * 70)

        print(f"\n📈 PERFORMANCE:")
        print(f"  Rate:                {summary.get('processing_rate_tx_per_sec', 0)} tx/s")
        print(f"  Total Time:          {summary.get('total_time_seconds', 0):.2f}s")
        print(f"  Total Transactions:  {summary.get('total_transactions', 0):,}")

        print(f"\n📊 STATUS:")
        print(f"  ✓ Included:          {summary.get('included', 0):,}")
        print(f"  ✗ Dropped:           {summary.get('dropped', 0):,}")
        print(f"  Drop Rate:           {summary.get('dropped_rate_percentage', 0)}%")

        tx_types = summary.get("tx_types", {})
        print(f"\n📦 TYPES:")
        print(f"  Legacy (Type 0):     {tx_types.get(0, 0):,}")
        print(f"  EIP-2930 (Type 1):   {tx_types.get(1, 0):,}")
        print(f"  EIP-1559 (Type 2):   {tx_types.get(2, 0):,}")

        time_stats = summary.get("time_stats", {})
        print(f"\n⏱️  TIME IN POOL:")
        print(f"  Min:                 {time_stats.get('min', 0):.2f}s")
        print(f"  Max:                 {time_stats.get('max', 0):.2f}s")
        print(f"  Avg:                 {time_stats.get('avg', 0):.2f}s")
        print(f"  Median:              {time_stats.get('median', 0):.2f}s")

        print(f"\n💾 FILES:")
        print(f"  CSV:                 {summary.get('csv_file', 'N/A')}")
        print(f"  Parquet:             {summary.get('parquet_file', 'N/A')}")

        print("\n" + "=" * 70 + "\n")


def main():
    """Main entry point."""
    DB_PATH = "../tx_data.db"
    NODE_URL = "http://localhost:8545"
    NUM_WORKERS = 100
    USE_CACHE = True
    CACHE_WRITE_INTERVAL = 30
    BATCH_SIZE = 500
    RPC_BATCH_SIZE = 100
    WRITE_BATCH_SIZE = 10000

    if len(sys.argv) > 1:
        NODE_URL = sys.argv[1]
    if len(sys.argv) > 2:
        DB_PATH = sys.argv[2]
    if len(sys.argv) > 3:
        NUM_WORKERS = int(sys.argv[3])
    if len(sys.argv) > 4:
        USE_CACHE = sys.argv[4].lower() == "true"
    if len(sys.argv) > 5:
        CACHE_WRITE_INTERVAL = int(sys.argv[5])
    if len(sys.argv) > 6:
        BATCH_SIZE = int(sys.argv[6])
    if len(sys.argv) > 7:
        RPC_BATCH_SIZE = int(sys.argv[7])
    if len(sys.argv) > 8:
        WRITE_BATCH_SIZE = int(sys.argv[8])

    print(f"🔧 Configuration:")
    print(f"  Database:            {DB_PATH}")
    print(f"  Node URL:            {NODE_URL}")
    print(f"  Workers:             {NUM_WORKERS}")
    print(f"  Processing Batch:    {BATCH_SIZE}")
    print(f"  RPC Batch:           {RPC_BATCH_SIZE}")
    print(f"  Write Batch:         {WRITE_BATCH_SIZE}\n")

    try:
        analyzer = FastTransactionAnalyzer(
            DB_PATH,
            node_url=NODE_URL,
            num_workers=NUM_WORKERS,
            use_cache=USE_CACHE,
            cache_write_interval=CACHE_WRITE_INTERVAL,
            batch_size=BATCH_SIZE,
            rpc_batch_size=RPC_BATCH_SIZE,
            write_batch_size=WRITE_BATCH_SIZE,
        )

        summary = asyncio.run(analyzer.calculate_metrics_async())
        analyzer.print_summary(summary)

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()