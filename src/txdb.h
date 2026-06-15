// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h>
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <sync.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

class COutPoint;
class uint256;

//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 64 << 20;

//! -coinsnegcachesize default (MiB). Bounds the absent-outpoint LRU; 0 disables.
static constexpr int64_t nDefaultCoinsNegCacheSizeMiB = 32;

//! User-controlled performance and debug options.
struct CoinsViewOptions {
    //! Maximum database write batch size in bytes.
    size_t batch_write_bytes = nDefaultDbBatchSize;
    //! If non-zero, randomly exit when the database is flushed with (1/ratio)
    //! probability.
    int simulate_crash_ratio = 0;
    //! Memory budget (bytes) for the negative-coin cache. 0 disables it.
    int64_t negative_cache_bytes = 0;
};

/**
 * Bounded, exact LRU set of outpoints known to be ABSENT from the on-disk UTXO
 * set. Repeated lookups for the same missing coin (e.g. an orphan-parent flood,
 * where a node re-validates the same unresolvable orphans many times) are then
 * answered without re-reading the chainstate leveldb. Those redundant reads are
 * what charge leveldb "seeks" and drive background seek-compaction CPU.
 *
 * Must be exact: a false "absent" would wrongly drop a valid coin, so a
 * probabilistic filter (Bloom) is unsafe here. Correctness relies on the on-disk
 * UTXO set changing only via CCoinsViewDB::BatchWrite(), which calls Clear();
 * mempool-created coins live in a view layered above CCoinsViewDB, so a DB-absent
 * coin cannot reappear at this layer between writes.
 */
class NegativeCoinCache
{
public:
    explicit NegativeCoinCache(size_t max_entries) : m_max_entries{max_entries} {}

    bool enabled() const { return m_max_entries > 0; }

    //! Whether the outpoint is cached as absent; on a hit, bumps it to most-recently-used.
    bool Contains(const COutPoint& outpoint);
    //! Record an outpoint as absent, evicting the least-recently-used entry if full.
    void Insert(const COutPoint& outpoint);
    //! Drop all entries (the underlying UTXO set changed).
    void Clear();

private:
    const size_t m_max_entries;
    mutable Mutex m_mutex;
    //! Recency order, front = most-recently-used. m_index maps an outpoint to its node.
    std::list<COutPoint> m_lru GUARDED_BY(m_mutex);
    std::unordered_map<COutPoint, std::list<COutPoint>::iterator, SaltedOutpointHasher> m_index GUARDED_BY(m_mutex);
    uint64_t m_lookups GUARDED_BY(m_mutex){0};
    uint64_t m_hits GUARDED_BY(m_mutex){0};
};

/** CCoinsView backed by the coin database (chainstate/)
 * Cursor requires FlushStateToDisk for consistency.
 */
class CCoinsViewDB final : public CCoinsView
{
protected:
    DBParams m_db_params;
    CoinsViewOptions m_options;
    std::unique_ptr<CDBWrapper> m_db;
    //! Caches outpoints found absent in m_db so repeated misses skip leveldb.
    mutable NegativeCoinCache m_neg_cache;
public:
    explicit CCoinsViewDB(DBParams db_params, CoinsViewOptions options);

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) override;
    std::unique_ptr<CCoinsViewCursor> Cursor() const override;

    //! Whether an unsupported database format is used.
    bool NeedsUpgrade();
    size_t EstimateSize() const override;

    //! Dynamically alter the underlying leveldb cache size.
    void ResizeCache(size_t new_cache_size) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    //! @returns filesystem path to on-disk storage or std::nullopt if in memory.
    std::optional<fs::path> StoragePath() { return m_db->StoragePath(); }
};

#endif // BITCOIN_TXDB_H
