#!/usr/bin/env python3
"""Reorg across a retarget boundary, with the contiguous-window rule active.

The rule is a pure function of the chain it is handed, so a reorg should simply
re-evaluate it against the new ancestor. That is worth testing rather than assuming,
because the rule reaches one block further back than the old one did, so the block it
measures from is one the reorg may have replaced.

Two chains fork before a retarget boundary and carry different timestamps, so they
require different work at the boundary. The node follows the first, then reorgs to the
second, and must end up with the second's difficulty rather than a stale value.
"""

from test_framework.util import assert_equal

from feature_timewarp_hardfork import GENESIS_TIME, INTERVAL, SIGNET_BLOCK_TIME, TimewarpTest

SPACING = SIGNET_BLOCK_TIME
RETARGET_HEIGHT = 2 * INTERVAL          # 32
# Fork BELOW the block the new rule measures from. The retarget at height 32 has
# pindexLast at 31, so the contiguous window starts at height 15; forking at 14
# means the reorg genuinely replaces that window-start block rather than only
# the tip, which is the case worth testing.
FORK_POINT = RETARGET_HEIGHT - INTERVAL - 2
HARDFORK_TIME = GENESIS_TIME            # active from the first block

# What the contiguous window yields for branch B at height 32. Under the current
# rule the window is one block shorter and this differs.
EXPECTED_REORGED_BITS = "1e0364e4"


class TimewarpReorgTest(TimewarpTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 2
        base = ["-signetchallenge=51", f"-signetblocktime={SIGNET_BLOCK_TIME}",
                f"-hardforktime={HARDFORK_TIME}"]
        self.extra_args = [base, base]

    def build_on(self, node, ntime):
        block = self.build(node, ntime)
        assert_equal(node.submitblock(block.serialize().hex()), None)
        return block

    def run_test(self):
        main, alt = self.nodes

        # Common history, fed to both nodes.
        common = []
        for height in range(1, FORK_POINT + 1):
            block = self.build(main, GENESIS_TIME + height * SPACING)
            for node in (main, alt):
                assert_equal(node.submitblock(block.serialize().hex()), None)
            common.append(block)
        assert_equal(main.getbestblockhash(), alt.getbestblockhash())
        self.log.info(f"common history to height {FORK_POINT}")

        # Branch A on `main`: tight spacing into the boundary.
        for height in range(FORK_POINT + 1, RETARGET_HEIGHT):
            self.build_on(main, GENESIS_TIME + height * SPACING + 1)
        bits_a = main.getblocktemplate({"rules": ["segwit", "signet"]})["bits"]

        # Branch B on `alt`: the same heights, much later timestamps, so the span the
        # retarget measures differs and so does the work it requires.
        alt_blocks = []
        for height in range(FORK_POINT + 1, RETARGET_HEIGHT):
            alt_blocks.append(self.build_on(alt, GENESIS_TIME + height * SPACING + 50000))
        bits_b = alt.getblocktemplate({"rules": ["segwit", "signet"]})["bits"]

        self.log.info(f"at the boundary: branch A wants {bits_a}, branch B wants {bits_b}")
        assert bits_a != bits_b, "branches did not diverge in required work"

        # Extend B so it outweighs A, then feed the whole of B to `main` and reorg it.
        alt_blocks.append(self.build_on(alt, GENESIS_TIME + RETARGET_HEIGHT * SPACING + 50000))
        for block in alt_blocks:
            # Rejections surface here with a name rather than as an opaque tip mismatch.
            result = main.submitblock(block.serialize().hex())
            assert result in (None, "inconclusive"), result

        assert_equal(main.getbestblockhash(), alt.getbestblockhash())
        assert_equal(main.getblockcount(), RETARGET_HEIGHT)
        self.log.info(f"reorged to branch B, tip height {main.getblockcount()}")

        # The retarget must reflect branch B's timestamps, not a value left over from A,
        # and must be the value the contiguous window produces. Pinned absolutely: every
        # other assertion here is node-vs-node agreement, which the old rule satisfies
        # too, so without this literal the whole test passes with the change reverted.
        reorged = main.getblockheader(main.getbestblockhash())["bits"]
        assert_equal(reorged, bits_b)
        assert_equal(reorged, EXPECTED_REORGED_BITS)
        assert_equal(main.getblocktemplate({"rules": ["segwit", "signet"]})["bits"],
                     alt.getblocktemplate({"rules": ["segwit", "signet"]})["bits"])
        self.log.info(f"retarget after the reorg is branch B's {reorged}, not branch A's {bits_a}")


if __name__ == "__main__":
    TimewarpReorgTest(__file__).main()
