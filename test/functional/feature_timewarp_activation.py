#!/usr/bin/env python3
"""Activation semantics of the contiguous-window rule, on a live chain.

Two claims about the rule in src/pow.cpp need to be falsifiable rather than asserted:

  1. The trigger is compared against the block's own timestamp, matching the proof of
     work rule, so nothing the fork carries activates in a different block from the
     rest. This is a consensus rule with no policy counterpart, since nBits is a single
     value the miner must know in advance.
  2. A retarget period whose blocks all predate the trigger is still measured under the
     new rule, if the block closing it has reached the trigger. Nothing is
     grandfathered and no state is carried across activation.

The trigger is placed so that exactly one of the three candidate clocks reaches it:

    parent's median time past   t(26)   below the trigger
    parent's own timestamp      t(31)   below the trigger
    the block's own timestamp   t(32)   at the trigger

So an implementation keyed to either of the first two produces the same nBits as a node
that never activates, and this test fails. `probe`, whose trigger sits one block above
the block's own timestamp, is the other side of the same check: nothing activates early.
"""

from test_framework.util import assert_equal

from feature_timewarp_hardfork import GENESIS_TIME, INTERVAL, SIGNET_BLOCK_TIME, TimewarpTest

# Honest spacing, so both rules land inside the clamps and produce different nBits.
SPACING = SIGNET_BLOCK_TIME

RETARGET_HEIGHT = 2 * INTERVAL  # 32, the first retarget after the period [16, 31]

# Exactly the timestamp of the block that closes the period, and above both the
# timestamp and the median time past of its parent.
HARDFORK_TIME = GENESIS_TIME + RETARGET_HEIGHT * SPACING

# One block later: reached by nothing here, so this node must not diverge.
PROBE_TIME = GENESIS_TIME + (RETARGET_HEIGHT + 1) * SPACING


class TimewarpActivationTest(TimewarpTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 3
        base = ["-signetchallenge=51", f"-signetblocktime={SIGNET_BLOCK_TIME}"]
        self.extra_args = [
            base + [f"-hardforktime={HARDFORK_TIME}"],
            base + [f"-hardforktime={PROBE_TIME}"],
            base,
        ]

    def run_test(self):
        activating, probe, never = self.nodes
        nodes = (activating, probe, never)

        # The whole period predates the trigger, so all three agree throughout it.
        for height in range(1, RETARGET_HEIGHT):
            block = self.build(activating, GENESIS_TIME + height * SPACING)
            for node in nodes:
                assert_equal(node.submitblock(block.serialize().hex()), None)
            assert_equal(len({node.getbestblockhash() for node in nodes}), 1)

        assert_equal(activating.getblockcount(), RETARGET_HEIGHT - 1)
        tip = activating.getblockheader(activating.getbestblockhash())
        assert tip["mediantime"] < HARDFORK_TIME, "parent's median time past reached it"
        assert tip["time"] < HARDFORK_TIME, "parent's own timestamp reached it"
        self.log.info(f"period [{INTERVAL}, {RETARGET_HEIGHT - 1}] is entirely before the "
                      f"trigger: parent time={tip['time']} mtp={tip['mediantime']} "
                      f"trigger={HARDFORK_TIME}")

        # The template's bits are load-bearing: create_block takes nBits straight from
        # it, and the node's real clock is far past the trigger, so UpdateTime() stamps
        # fork-rule bits into it. That makes this the only coverage of the miner.cpp
        # change outside the unit tests. The submitted block's own timestamp is what
        # each node then judges those bits against.
        block = self.build(activating, HARDFORK_TIME)
        assert_equal(block.nTime, HARDFORK_TIME)
        assert_equal(activating.submitblock(block.serialize().hex()), None)
        assert_equal(activating.getblockcount(), RETARGET_HEIGHT)

        # Keyed to the block's own timestamp, only `activating` wanted the new window.
        for node, name in ((probe, "probe"), (never, "never")):
            assert_equal(node.submitblock(block.serialize().hex()), "bad-diffbits")
            assert_equal(node.getblockcount(), RETARGET_HEIGHT - 1)
            self.log.info(f"{name} rejected it as bad-diffbits, as it must")

        new_bits = activating.getblockheader(activating.getbestblockhash())["bits"]
        old_bits = never.getblocktemplate({"rules": ["segwit", "signet"]})["bits"]
        assert new_bits != old_bits
        self.log.info(f"retarget at height {RETARGET_HEIGHT}: fork rule {new_bits}, "
                      f"current rule {old_bits}; trigger is the block's own timestamp")


if __name__ == "__main__":
    TimewarpActivationTest(__file__).main()
