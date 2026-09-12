// Copyright (c) 2026 The Bitcoin Knots developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>

#include <boost/test/unit_test.hpp>

#include <limits>

BOOST_FIXTURE_TEST_SUITE(coinbase_maturity_tests, BasicTestingSetup)

// Only outputs created at or after the start height are covered, and only
// until RDTS expires.
BOOST_AUTO_TEST_CASE(maturity_in_force_window)
{
    constexpr int H{1000};
    constexpr int64_t E{2'000'000'000};
    Consensus::Params params;
    params.CoinbaseMaturityLongStartHeight = H;
    params.RdtsExpiryTime = E;

    for (const int64_t mtp : {int64_t{0}, E - 1}) {
        const CoinbaseMaturity maturity{params.CoinbaseMaturityInForce(mtp)};
        BOOST_CHECK_EQUAL(maturity.Required(H - 1), COINBASE_MATURITY);
        BOOST_CHECK_EQUAL(maturity.Required(H), COINBASE_MATURITY_LONG);
        BOOST_CHECK_EQUAL(maturity.Required(H + 1), COINBASE_MATURITY_LONG);
    }
    for (const int64_t mtp : {E, E + 1}) {
        const CoinbaseMaturity maturity{params.CoinbaseMaturityInForce(mtp)};
        for (const int height : {0, H - 1, H, H + 1}) {
            BOOST_CHECK_EQUAL(maturity.Required(height), COINBASE_MATURITY);
        }
    }
}

// A schedule can never ask for less than the ordinary rule.
BOOST_AUTO_TEST_CASE(never_weaker_than_the_ordinary_rule)
{
    Consensus::Params params;
    params.CoinbaseMaturityLongStartHeight = 0;
    params.RdtsExpiryTime = std::numeric_limits<int64_t>::max();
    for (const int depth : {0, 1, COINBASE_MATURITY - 1, COINBASE_MATURITY, COINBASE_MATURITY_LONG}) {
        params.CoinbaseMaturityLong = depth;
        BOOST_CHECK(params.CoinbaseMaturityInForce(0).Required(0) >= COINBASE_MATURITY);
    }
}

// Unscheduled is the default, and then no output is ever covered.
BOOST_AUTO_TEST_CASE(unscheduled_is_inert)
{
    const Consensus::Params defaults{};
    for (const int64_t mtp : {std::numeric_limits<int64_t>::min(), int64_t{0},
                              int64_t{2'000'000'000}, std::numeric_limits<int64_t>::max()}) {
        const CoinbaseMaturity maturity{defaults.CoinbaseMaturityInForce(mtp)};
        for (const int height : {0, 1, 970650, std::numeric_limits<int>::max() - 1}) {
            BOOST_CHECK_EQUAL(maturity.Required(height), COINBASE_MATURITY);
        }
    }

    for (const auto chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
        // Hold the params alive: GetConsensus() returns a reference into them.
        const auto params{CreateChainParams(*m_node.args, chain)};
        const Consensus::Params& consensus{params->GetConsensus()};
        BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityLongStartHeight, std::numeric_limits<int>::max());
        for (const int64_t mtp : {int64_t{0}, int64_t{std::numeric_limits<uint32_t>::max()}}) {
            BOOST_CHECK_EQUAL(consensus.CoinbaseMaturityInForce(mtp).Required(970650), COINBASE_MATURITY);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
