// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/coins_view_args.h>

#include <common/args.h>
#include <txdb.h>

#include <algorithm>

namespace node {
void ReadCoinsViewArgs(const ArgsManager& args, CoinsViewOptions& options)
{
    if (auto value = args.GetIntArg("-dbbatchsize")) options.batch_write_bytes = *value;
    if (auto value = args.GetIntArg("-dbcrashratio")) options.simulate_crash_ratio = *value;
    options.negative_cache_bytes = std::max<int64_t>(0, args.GetIntArg("-coinsnegcachesize", nDefaultCoinsNegCacheSizeMiB)) << 20;
}
} // namespace node
