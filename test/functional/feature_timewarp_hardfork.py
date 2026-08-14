#!/usr/bin/env python3
"""Timewarp attack against live nodes, on a custom signet with a short retarget interval.

Coverage for the timewarp attack and the contiguous retarget windows that fix it.
The rule and its activation are stated at the change site in src/pow.cpp.

Three nodes see the same attack:
  node0  no trigger configured
  node1  fork rules active from the start of the chain
  node2  a trigger set to a time the chain never reaches

node0 and node2 are fed byte-identical blocks and must agree at every step, which shows
that setting a trigger the chain never reaches changes nothing. Both are the patched
binary, so that is all it shows; CURRENT_RULE_END below pins the end state absolutely,
which is what a run against an unpatched binary can be compared against.

node1 mines its own chain, because under the fork rule the attack produces different
difficulty and so different blocks.

The retarget interval is shortened with -signetblocktime so the attack runs in minutes
rather than years. The seam being exercised does not depend on the interval: the window
for the retarget at height R is [R-N, R-1], which spans N blocks but only N-1
inter-block intervals, so the gap between R-1 and R is measured by nothing.
"""

import subprocess

from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CBlockHeader, from_hex
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

INTERVAL = 16                                    # blocks per retarget period
SIGNET_BLOCK_TIME = 1209600 // INTERVAL           # keeps nPowTargetTimespan at 14 days
GENESIS_TIME = 1598918400                         # signet genesis nTime

WARMUP_EPOCHS = 2                                 # lift difficulty off the powLimit floor
ATTACK_EPOCHS = 3
SPIKE_OFFSET = 60 * 24 * 60 * 60                  # 60 days, past the 4x clamp at 56 days

NEVER = 2000000000                                # a trigger the chain never reaches

# Where the attack leaves a chain running today's rules. Asserted by this test and by
# feature_timewarp_unpatched.py, so that the patched binary with an unreached trigger
# and a binary with no patch at all are pinned to the same consensus outcome.
CURRENT_RULE_END = {"height": (WARMUP_EPOCHS + ATTACK_EPOCHS) * INTERVAL, "bits": "1e0377ae"}


class TimewarpTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.setup_clean_chain = True
        self.num_nodes = 3
        base = ["-signetchallenge=51", f"-signetblocktime={SIGNET_BLOCK_TIME}"]
        self.extra_args = [
            base,
            base + [f"-hardforktime={GENESIS_TIME}"],
            base + [f"-hardforktime={NEVER}"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_bitcoin_util()

    def setup_network(self):
        self.setup_nodes()  # deliberately unconnected: three independent chains

    def build(self, node, ntime):
        tmpl = node.getblocktemplate({"rules": ["segwit", "signet"]})
        block = create_block(int(tmpl["previousblockhash"], 16),
                             create_coinbase(height=tmpl["height"]),
                             ntime, tmpl=tmpl)
        add_witness_commitment(block)
        head = CBlockHeader.serialize(block).hex()
        out = subprocess.run([self.options.bitcoinutil, "grind", head],
                             stdout=subprocess.PIPE, input=b"", check=True).stdout.strip()
        block.nNonce = from_hex(CBlockHeader(), out.decode()).nNonce
        block.rehash()
        return block

    def schedule(self, height, epoch_kind, epoch_index):
        """The attacker's timestamp for a block at this height."""
        if epoch_kind == "attack" and height % INTERVAL == INTERVAL - 1:
            return GENESIS_TIME + SPIKE_OFFSET + epoch_index
        return GENESIS_TIME + height

    def run_epoch(self, nodes, kind, index):
        for _ in range(INTERVAL):
            height = nodes[0].getblockcount() + 1
            block = self.build(nodes[0], self.schedule(height, kind, index))
            for node in nodes:
                assert_equal(node.submitblock(block.serialize().hex()), None)
            tips = {node.getbestblockhash() for node in nodes}
            assert_equal(len(tips), 1)

    def state(self, node):
        tip = node.getblockheader(node.getbestblockhash())
        nxt = node.getblocktemplate({"rules": ["segwit", "signet"]})
        return tip["height"], tip["time"], tip["difficulty"], nxt["bits"]

    def report(self, node, label):
        height, time, difficulty, bits = self.state(node)
        self.log.info(f"{label}: height={height} tip_time={time} "
                      f"difficulty={difficulty} next_bits={bits}")
        return difficulty, time

    def run_chain(self, nodes, label):
        for e in range(WARMUP_EPOCHS):
            self.run_epoch(nodes, "warmup", e)
            self.report(nodes[0], f"{label} warmup {e}")

        start_difficulty, start_time = self.report(nodes[0], f"{label} attack start")
        for e in range(ATTACK_EPOCHS):
            self.run_epoch(nodes, "attack", e)
            self.report(nodes[0], f"{label} attack epoch {e}")
        end_difficulty, end_time = self.report(nodes[0], f"{label} attack end")

        self.log.info(f"RESULT {label}: difficulty {start_difficulty} -> {end_difficulty} "
                      f"(x{end_difficulty / start_difficulty:.4f}) while the chain's own "
                      f"clock advanced {end_time - start_time}s over "
                      f"{ATTACK_EPOCHS * INTERVAL} blocks")
        return start_difficulty, end_difficulty

    def check_current_rule_end(self, node):
        height, _, _, bits = self.state(node)
        self.log.info(f"current-rules end state: height={height} bits={bits} "
                      f"tip={node.getbestblockhash()}")
        assert_equal({"height": height, "bits": bits}, CURRENT_RULE_END)

    def run_test(self):
        current, fork, gated = self.nodes
        self.log.info(f"interval={INTERVAL} blocks, target timespan=1209600s, "
                      f"spacing={SIGNET_BLOCK_TIME}s")

        # node0 and node2 receive identical blocks and must stay in lockstep.
        before, after = self.run_chain([current, gated], "current rule")
        assert after < before, "timewarp failed to lower difficulty under current rules"
        assert_equal(current.getbestblockhash(), gated.getbestblockhash())
        assert_equal(self.state(current), self.state(gated))
        self.log.info("an unreached trigger changed nothing at any block")
        self.check_current_rule_end(current)

        f_before, f_after = self.run_chain([fork], "fork rule")
        assert f_after >= f_before, "timewarp lowered difficulty under fork rules"


if __name__ == "__main__":
    TimewarpTest(__file__).main()
