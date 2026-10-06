#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test that a crash during the post-IBD chainstate sync leaves a node that restarts.

The coins database records the block it is moving to before a partial write, so
the block index must already be on disk when that write starts. Otherwise a
crash in the middle of it leaves the coins database pointing at a block the
block index does not have, and the node cannot start again without
-reindex-chainstate.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

SYNC_CHECK_INTERVAL = 30


class PostIBDSyncCrashTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Crash on the first partial write of the coins database.
        self.extra_args = [["-dbcrashratio=1", "-dbbatchsize=1"]]

    def run_test(self):
        node = self.nodes[0]
        self.generate(node, 10)
        height = node.getblockcount()

        self.log.info("Crash in the middle of the post-IBD chainstate sync")
        # The first check sees a new height and reschedules; the second syncs
        # and the node crashes. A slow machine can already have run the first
        # check in real time, so either call may be the one that crashes it.
        for _ in range(2):
            try:
                node.mockscheduler(SYNC_CHECK_INTERVAL)
            except Exception:
                break
        node.wait_until_stopped()
        with open(node.debug_log_path, encoding="utf-8") as f:
            log = f.read()
        assert "Finished syncing to tip, syncing chainstate to disk" in log
        assert "Simulating a crash" in log

        self.log.info("Verify the node restarts at the same height")
        self.start_node(0, extra_args=[])
        assert_equal(node.getblockcount(), height)


if __name__ == '__main__':
    PostIBDSyncCrashTest(__file__).main()
