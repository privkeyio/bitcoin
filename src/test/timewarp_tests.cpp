// Coverage for the timewarp attack and the contiguous retarget windows that fix it.
// The rule and its activation are stated at the change site in src/pow.cpp.
//
// Everything here drives the real GetNextWorkRequired()/CalculateNextWorkRequired()
// against mainnet consensus parameters and the real CBlockIndex::GetMedianTimePast(),
// so the difficulty arithmetic is production code. What is modelled rather than
// measured is the attacker's hash rate, marked ASSUMPTION where it is used.
//
// Height convention, since every test depends on it: GetNextWorkRequired(pindexLast)
// retargets when (pindexLast->nHeight + 1) % 2016 == 0, so a retarget is available
// only when the tip sits at height 2016k - 1. Each test primes the chain to such a
// height before measuring anything.

#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <node/miner.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(timewarp_tests, BasicTestingSetup)

namespace {

//! Arbitrary attack start time; nothing depends on its value.
constexpr int64_t T_START{1700000000};

//! nBits for a difficulty 2^shift above the chain's minimum.
uint32_t BitsAboveFloor(const Consensus::Params& params, int shift)
{
    arith_uint256 target = UintToArith256(params.powLimit);
    target >>= shift;
    return target.GetCompact();
}

//! The measured timespan as the retarget will actually use it.
double Clamped(int64_t span, const Consensus::Params& params)
{
    return static_cast<double>(std::clamp<int64_t>(span, params.nPowTargetTimespan / 4,
                                                   params.nPowTargetTimespan * 4));
}

double DifficultyOf(uint32_t nbits, const Consensus::Params& params)
{
    arith_uint256 target;
    target.SetCompact(nbits);
    return UintToArith256(params.powLimit).getdouble() / target.getdouble();
}

struct ChainSim {
    std::vector<CBlockIndex> blocks;
    Consensus::Params params;
    size_t n{0};

    ChainSim(size_t cap, const Consensus::Params& p) : blocks(cap), params(p) {}

    CBlockIndex* Tip() { return &blocks[n - 1]; }

    void Start(int64_t ntime, uint32_t nbits)
    {
        blocks[0].pprev = nullptr;
        blocks[0].nHeight = 0;
        blocks[0].nTime = static_cast<uint32_t>(ntime);
        blocks[0].nBits = nbits;
        blocks[0].BuildSkip();
        n = 1;
    }

    //! The work a block with this timestamp would need. The fork rule reads the
    //! block's own timestamp, so the candidate time is part of the question.
    uint32_t NextBits(int64_t ntime)
    {
        CBlockHeader header;
        header.nTime = static_cast<uint32_t>(ntime);
        return GetNextWorkRequired(Tip(), &header, params);
    }

    uint32_t NextBits() { return NextBits(Tip()->nTime + 1); }

    void Add(int64_t ntime)
    {
        CBlockIndex& b = blocks[n];
        b.pprev = &blocks[n - 1];
        b.nHeight = static_cast<int>(n);
        b.nBits = NextBits(ntime);
        b.nTime = static_cast<uint32_t>(ntime);
        b.BuildSkip();
        ++n;
    }

    //! Lowest timestamp consensus permits for the next block.
    int64_t MinNextTime() { return Tip()->GetMedianTimePast() + 1; }

    int64_t TimeAt(int64_t height) const { return static_cast<int64_t>(blocks[height].nTime); }
};

//! Honest mining: blocks arrive at exactly the target spacing.
void HonestBlocks(ChainSim& c, int64_t count)
{
    for (int64_t i = 0; i < count; ++i) c.Add(c.Tip()->nTime + c.params.nPowTargetSpacing);
}

//! Prime a chain to height 2016k - 1, the only height at which a retarget follows.
void PrimeToRetarget(ChainSim& c)
{
    HonestBlocks(c, c.params.DifficultyAdjustmentInterval() - 1);
}

} // namespace

// The window for the retarget at height R is [R-2016, R-1]: 2016 blocks but only
// 2015 inter-block intervals. On an honest chain running at exactly the target
// spacing that under-measures each period by one spacing, so difficulty drifts up.
BOOST_AUTO_TEST_CASE(off_by_one_biases_honest_chain)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int64_t interval = params.DifficultyAdjustmentInterval();
    BOOST_CHECK_EQUAL(interval, 2016);

    ChainSim c(3 * interval + 2, params);
    c.Start(T_START, UintToArith256(params.powLimit).GetCompact());
    PrimeToRetarget(c);
    const uint32_t before = c.NextBits();
    HonestBlocks(c, interval);
    const uint32_t after = c.NextBits();

    arith_uint256 t_before, t_after;
    t_before.SetCompact(before);
    t_after.SetCompact(after);
    const double ratio = t_after.getdouble() / t_before.getdouble();

    BOOST_TEST_MESSAGE("honest chain, current rule: target ratio per period = "
                       << ratio << " (2015/2016 = " << 2015.0 / 2016.0 << ")");
    BOOST_CHECK_CLOSE(ratio, 2015.0 / 2016.0, 0.01);

    // Same chain, fork rules active: the window is contiguous and the bias is gone.
    Consensus::Params fixed = params;
    fixed.HardforkTime = 0;
    ChainSim f(3 * interval + 2, fixed);
    f.Start(T_START, UintToArith256(params.powLimit).GetCompact());
    PrimeToRetarget(f);
    const uint32_t f_before = f.NextBits();
    HonestBlocks(f, interval);
    const uint32_t f_after = f.NextBits();
    BOOST_TEST_MESSAGE("honest chain, fork rule: bits " << std::hex << f_before << " -> "
                       << f_after << std::dec);
    BOOST_CHECK_EQUAL(f_before, f_after);
}

namespace {

struct AttackResult {
    int periods_to_floor{0};
    double real_days{0};
    int64_t chain_seconds{0};
    std::vector<double> difficulty;
};

// The classic timewarp: every block in a period takes the lowest timestamp consensus
// permits, except the last block of the period, which is pushed as far into the
// future as the node's own clock allows. The next period's first block drops back
// down, and the interval between the two is measured by nothing.
//
// ASSUMPTION (the only one): the attacker holds all the hash rate that was producing
// blocks at the starting difficulty, so a block takes 600s * D_now / D_start of real
// time. Real time is what bounds the spike, through MAX_FUTURE_BLOCK_TIME.
AttackResult RunTimewarp(const Consensus::Params& params, uint32_t start_bits, int max_periods)
{
    const int64_t interval = params.DifficultyAdjustmentInterval();
    ChainSim c(static_cast<size_t>(interval) * (max_periods + 1) + 2, params);
    c.Start(T_START, start_bits);
    PrimeToRetarget(c);

    const double d_start = DifficultyOf(start_bits, params);
    const uint32_t floor_bits = UintToArith256(params.powLimit).GetCompact();
    double real_now = static_cast<double>(c.Tip()->nTime);
    // Everything is measured from the attacker's first block, not from the chain's
    // start, so the honest history used to prime the chain is not counted.
    const double real_at_attack_start = real_now;
    const int64_t mtp_at_attack_start = c.Tip()->GetMedianTimePast();

    AttackResult r;
    for (int period = 0; period < max_periods; ++period) {
        for (int64_t i = 0; i < interval; ++i) {
            const double d_now = DifficultyOf(c.NextBits(), params);
            real_now += params.nPowTargetSpacing * d_now / d_start; // ASSUMPTION
            if (i == interval - 1) {
                // Close the period as far forward as the clock permits.
                const int64_t ceiling = static_cast<int64_t>(real_now) + MAX_FUTURE_BLOCK_TIME;
                c.Add(std::max(c.MinNextTime(), ceiling));
            } else {
                c.Add(c.MinNextTime());
            }
        }
        const uint32_t bits = c.NextBits();
        r.difficulty.push_back(DifficultyOf(bits, params));
        if (bits == floor_bits) {
            r.periods_to_floor = period + 1;
            r.real_days = (real_now - real_at_attack_start) / 86400.0;
            r.chain_seconds = c.Tip()->GetMedianTimePast() - mtp_at_attack_start;
            break;
        }
    }
    return r;
}

} // namespace

// The attack, measured. Starting difficulty is 4^24 above the mainnet floor, chosen
// as the order of magnitude of mainnet difficulty; the per-period ratio and the
// real-time cost are what the numbers are for.
BOOST_AUTO_TEST_CASE(timewarp_attack_current_rule)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const uint32_t start_bits = BitsAboveFloor(params, 48);

    const AttackResult r = RunTimewarp(params, start_bits, 60);

    BOOST_TEST_MESSAGE("start difficulty " << DifficultyOf(start_bits, params));
    for (size_t i = 0; i < r.difficulty.size(); ++i) {
        const double prev = i == 0 ? DifficultyOf(start_bits, params) : r.difficulty[i - 1];
        BOOST_TEST_MESSAGE("  period " << i << ": difficulty " << r.difficulty[i]
                           << "  (divided by " << prev / r.difficulty[i] << ")");
    }
    BOOST_TEST_MESSAGE("reached the floor after " << r.periods_to_floor << " periods, "
                       << r.real_days << " days of real time, while the chain's own"
                       " median time advanced " << r.chain_seconds << "s");

    BOOST_CHECK(r.periods_to_floor > 0);
    BOOST_CHECK(r.real_days < 365);
}

// Same attack, fork rules active. Each window starts where the previous one ended,
// so the spike used to inflate one period is the baseline the next is measured from:
// manufactured time cancels instead of accumulating.
BOOST_AUTO_TEST_CASE(timewarp_attack_fork_rule)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.HardforkTime = 0;
    const uint32_t start_bits = BitsAboveFloor(params, 48);

    const AttackResult r = RunTimewarp(params, start_bits, 60);

    for (size_t i = 0; i < r.difficulty.size() && i < 8; ++i) {
        BOOST_TEST_MESSAGE("  period " << i << ": difficulty " << r.difficulty[i]);
    }
    BOOST_TEST_MESSAGE("periods to floor under the fork rule: " << r.periods_to_floor
                       << " (0 means it never got there)");

    BOOST_CHECK_EQUAL(r.periods_to_floor, 0);
    const double d_start = DifficultyOf(start_bits, params);
    for (const double d : r.difficulty) BOOST_CHECK(d >= d_start * 0.9);
}

// The property the fix rests on: with contiguous windows every inter-block interval
// is measured exactly once, so measured spans telescope to the chain's total elapsed
// time. An attacker cannot manufacture measured time, only redistribute it. The
// current rule drops one interval per period, and that is the leak.
BOOST_AUTO_TEST_CASE(contiguous_windows_telescope)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int64_t interval = params.DifficultyAdjustmentInterval();
    const int periods = 5;
    const size_t cap = static_cast<size_t>(interval) * (periods + 1) + 2;

    auto fixed = params;
    fixed.HardforkTime = 0;
    ChainSim f(cap, fixed), c(cap, params);

    // Both chains get byte-identical timestamps: the schedule below depends only on
    // earlier timestamps, never on nBits, so the only difference between them is the
    // rule under test. Deliberately erratic, and consensus-valid throughout.
    uint32_t f_base{0}, c_base{0};
    for (ChainSim* s : {&f, &c}) {
        s->Start(T_START, BitsAboveFloor(params, 48));
        PrimeToRetarget(*s);
        (s == &f ? f_base : c_base) = s->NextBits();
        // Sized so a period lands well inside the 1/4x-4x clamps. Beyond them both
        // rules clamp to the same value and the seam stops being observable, which
        // is worth knowing: the clamps hide this bug rather than bound it.
        for (int p = 0; p < periods; ++p) {
            for (int64_t i = 0; i < interval; ++i) {
                const int64_t jump = (i % 7 == 0) ? 4000 : 1;
                s->Add(std::max(s->MinNextTime(), s->TimeAt(s->Tip()->nHeight) + jump));
            }
        }
    }
    BOOST_CHECK_EQUAL(f_base, c_base); // the first period is measured alike either way
    for (size_t i = 0; i < f.n; ++i) BOOST_REQUIRE_EQUAL(f.TimeAt(i), c.TimeAt(i));

    // Periods run [interval*p, interval*(p+1) - 1] for p = 1..periods. The measured
    // spans telescope under the fork rule and fall short under the current one.
    int64_t fork_total{0}, current_total{0};
    double fork_expected{1.0}, current_expected{1.0};
    for (int p = 1; p <= periods; ++p) {
        const int64_t last = interval * (p + 1) - 1;
        const int64_t fork_span = f.TimeAt(last) - f.TimeAt(last - interval);
        const int64_t current_span = f.TimeAt(last) - f.TimeAt(last - (interval - 1));
        fork_total += fork_span;
        current_total += current_span;
        fork_expected *= Clamped(fork_span, params) / static_cast<double>(params.nPowTargetTimespan);
        current_expected *= Clamped(current_span, params) / static_cast<double>(params.nPowTargetTimespan);
    }
    const int64_t actual = f.TimeAt(interval * (periods + 1) - 1) - f.TimeAt(interval - 1);

    BOOST_TEST_MESSAGE("over " << periods << " periods: actual elapsed " << actual
                       << "s, measured by the fork rule " << fork_total
                       << "s, measured by the current rule " << current_total << "s");
    BOOST_CHECK_EQUAL(fork_total, actual);
    BOOST_CHECK(current_total < actual);

    // The point of the test: the difficulty the real retarget code arrives at is the
    // one those measured spans predict. Reverting the one-line change fails this.
    const double base = DifficultyOf(f_base, params);
    const double fork_got = DifficultyOf(f.NextBits(), params) / base;
    const double current_got = DifficultyOf(c.NextBits(), params) / base;
    BOOST_TEST_MESSAGE("difficulty after those periods: fork rule x" << fork_got
                       << " (predicted x" << 1.0 / fork_expected << "), current rule x"
                       << current_got << " (predicted x" << 1.0 / current_expected << ")");
    BOOST_CHECK_CLOSE(fork_got, 1.0 / fork_expected, 0.5);
    BOOST_CHECK_CLOSE(current_got, 1.0 / current_expected, 0.5);
    // Under-measuring time leaves difficulty higher than the chain actually earned.
    BOOST_CHECK(current_got > fork_got);
}

// The clamps are the one gap in the telescoping argument, since a clamped period is
// not measured at its true value. Cycling them, taking a 4x rise to buy a 4x fall,
// is the residual attack shape. Under the fork rule the cycle nets out; under the
// current rule the seam pays for it and difficulty walks down.
BOOST_AUTO_TEST_CASE(clamp_cycling_under_fork_rule)
{
    const auto base = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int64_t interval = base.DifficultyAdjustmentInterval();
    const int cycles = 4;
    const uint32_t start_bits = BitsAboveFloor(base, 48);

    auto run = [&](bool fork) {
        auto params = base;
        if (fork) params.HardforkTime = 0;
        ChainSim c(static_cast<size_t>(interval) * (2 * cycles + 1) + 2, params);
        c.Start(T_START, start_bits);
        PrimeToRetarget(c);
        int64_t close = c.TimeAt(c.Tip()->nHeight);
        for (int p = 0; p < 2 * cycles; ++p) {
            // Alternate: a period that closes 60 days on, then one that closes 1s on.
            close += (p % 2 == 0) ? 5184000 : 1;
            for (int64_t i = 0; i < interval; ++i) {
                c.Add(i == interval - 1 ? std::max(c.MinNextTime(), close) : c.MinNextTime());
            }
        }
        return DifficultyOf(c.NextBits(), params) / DifficultyOf(start_bits, params);
    };

    const double fork_ratio = run(true);
    const double current_ratio = run(false);
    BOOST_TEST_MESSAGE("clamp cycling over " << cycles << " cycles: difficulty ends at "
                       << fork_ratio << "x of its start under the fork rule, "
                       << current_ratio << "x under the current rule");
    BOOST_CHECK_CLOSE(fork_ratio, 1.0, 1.0);
    BOOST_CHECK(current_ratio < 0.5);
}

// The trigger reads the block's own timestamp, so one parent can require different
// work of two candidate blocks that straddle it. That is the entire content of the
// keying. It is also why the combined tree has to keep getblocktemplate's mintime on
// the same side of the trigger as the bits it hands out; that clamp is not on this
// branch, it comes with the PoW change.
BOOST_AUTO_TEST_CASE(trigger_reads_the_block_timestamp)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int64_t interval = params.DifficultyAdjustmentInterval();

    // Two full periods, so the retarget is past the first-period guard.
    ChainSim c(2 * interval + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(c);
    HonestBlocks(c, interval);

    const int64_t below{c.TimeAt(c.Tip()->nHeight) + 1};
    const int64_t at{below + 100};

    // Inert: the candidate timestamp cannot matter before the fork.
    BOOST_CHECK_EQUAL(c.NextBits(below), c.NextBits(at));

    c.params.HardforkTime = at;
    const uint32_t old_rule{c.NextBits(below)};
    const uint32_t fork_rule{c.NextBits(at)};
    BOOST_TEST_MESSAGE("same parent, trigger at " << at << ": a block stamped " << below
                       << " needs " << std::hex << old_rule << ", one stamped " << std::dec
                       << at << " needs " << std::hex << fork_rule << std::dec);
    BOOST_CHECK(old_rule != fork_rule);

    // And the boundary is exactly at the trigger, not one either side of it.
    BOOST_CHECK_EQUAL(c.NextBits(at - 1), old_rule);
    BOOST_CHECK_EQUAL(c.NextBits(at + 1), fork_rule);
}

// UpdateTime() recomputes nBits on every chain rather than only where min-difficulty
// blocks are allowed, because required work now depends on the block's own timestamp.
// Without that, a template built before the trigger and refreshed after it keeps its
// pre-fork bits, and the block a miner returns from it is rejected as bad-diffbits at
// exactly the activation boundary.
BOOST_AUTO_TEST_CASE(update_time_refreshes_work_across_the_trigger)
{
    const auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    const int64_t interval = params.DifficultyAdjustmentInterval();

    ChainSim c(2 * interval + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(c);
    HonestBlocks(c, interval); // tip at 2*interval-1, so the next block retargets

    const int64_t trigger{c.TimeAt(c.Tip()->nHeight) + 10000};
    c.params.HardforkTime = trigger;

    CBlockHeader header;
    header.nTime = static_cast<uint32_t>(trigger - 1);
    header.nBits = c.NextBits(trigger - 1);

    SetMockTime(trigger - 1);
    node::UpdateTime(&header, c.params, c.Tip());
    const uint32_t before{header.nBits};

    SetMockTime(trigger + 1);
    node::UpdateTime(&header, c.params, c.Tip());
    const uint32_t after{header.nBits};
    SetMockTime(0);

    BOOST_TEST_MESSAGE("template refreshed across the trigger: bits " << std::hex << before
                       << " -> " << after << std::dec);
    BOOST_CHECK(before != after);
    BOOST_CHECK_EQUAL(before, c.NextBits(trigger - 1));
    BOOST_CHECK_EQUAL(after, c.NextBits(trigger + 1));
}

// The first period has no predecessor to measure from. That edge case is the reason
// the direct fix is called complicated, and it is the only thing the guard handles:
// on a chain activating partway along, height 0 is long past.
BOOST_AUTO_TEST_CASE(first_period_has_no_predecessor)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.HardforkTime = 0; // active from genesis, the hostile case for the guard
    const int64_t interval = params.DifficultyAdjustmentInterval();

    ChainSim c(static_cast<size_t>(interval) + 2, params);
    c.Start(T_START, UintToArith256(params.powLimit).GetCompact());
    PrimeToRetarget(c);
    const uint32_t got = c.NextBits(); // would be height -1 without the guard

    auto old_params = params;
    old_params.HardforkTime = std::numeric_limits<int64_t>::max();
    ChainSim o(static_cast<size_t>(interval) + 2, old_params);
    o.Start(T_START, UintToArith256(params.powLimit).GetCompact());
    PrimeToRetarget(o);
    BOOST_CHECK_EQUAL(got, o.NextBits());
}

// The guard and the window are arithmetic on the retarget interval, and mainnet's is
// not the only one: testnet4 differs, and a custom signet sets its own via
// -signetblocktime. Run the two properties that matter at a short interval too.
BOOST_AUTO_TEST_CASE(holds_at_other_retarget_intervals)
{
    const auto mainnet = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    for (const int64_t interval : {16, 144, 2016}) {
        auto params = mainnet;
        params.nPowTargetSpacing = params.nPowTargetTimespan / interval;
        BOOST_REQUIRE_EQUAL(params.DifficultyAdjustmentInterval(), interval);
        params.HardforkTime = 0; // active from genesis, the hostile case for the guard

        auto old_params = params;
        old_params.HardforkTime = std::numeric_limits<int64_t>::max();

        // First period: no predecessor, so the guard must fall back to the old window.
        ChainSim f(static_cast<size_t>(interval) * 2 + 2, params);
        ChainSim o(static_cast<size_t>(interval) * 2 + 2, old_params);
        for (ChainSim* s : {&f, &o}) {
            s->Start(T_START, UintToArith256(params.powLimit).GetCompact());
            PrimeToRetarget(*s);
        }
        BOOST_CHECK_EQUAL(f.NextBits(), o.NextBits());

        // Second period: the window is contiguous, so an honest chain at exactly the
        // target spacing holds its difficulty while the old rule ratchets it up.
        HonestBlocks(f, interval);
        HonestBlocks(o, interval);
        const uint32_t fork_before{f.blocks[interval].nBits}, fork_after{f.NextBits()};
        BOOST_TEST_MESSAGE("interval " << interval << ": fork rule " << std::hex << fork_before
                           << " -> " << fork_after << ", current rule -> " << o.NextBits()
                           << std::dec);
        BOOST_CHECK_EQUAL(fork_before, fork_after);
        BOOST_CHECK(o.NextBits() != fork_after);
    }
}

// Headers sync bounds every retarget with PermittedDifficultyTransition, which reads
// only the clamps. The fork rule changes which blocks are measured, not the clamps,
// so headers sync keeps working across the change.
BOOST_AUTO_TEST_CASE(permitted_transition_still_holds)
{
    auto params = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    params.HardforkTime = 0;
    const int64_t interval = params.DifficultyAdjustmentInterval();
    const int periods = 4;

    ChainSim c(static_cast<size_t>(interval) * (periods + 1) + 2, params);
    c.Start(T_START, BitsAboveFloor(params, 48));
    PrimeToRetarget(c);
    for (int p = 0; p < periods; ++p) {
        for (int64_t i = 0; i < interval; ++i) {
            const int64_t jump = (i == interval - 1) ? 4838400 : 1;
            c.Add(std::max(c.MinNextTime(), c.TimeAt(c.Tip()->nHeight) + jump));
        }
        BOOST_CHECK(PermittedDifficultyTransition(params, c.Tip()->nHeight + 1,
                                                  c.Tip()->nBits, c.NextBits()));
    }
}

BOOST_AUTO_TEST_SUITE_END()
