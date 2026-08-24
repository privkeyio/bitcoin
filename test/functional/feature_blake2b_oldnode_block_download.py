#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Knots developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Confirm old nodes are still used to download blocks after the full header chain.

Luke's gated criterion: we do not sync blocks from old nodes until we have the full
header chain, which past the fork includes BLAKE2b (v2) headers; once we have it, we
must still download blocks from old (non-NODE_BLAKE2B) peers.

A fork-scheduled node is given the full header chain across the BLAKE2b fork via
submitheader (headers only, no block data). Its only peer is a non-NODE_BLAKE2B peer,
demoted to stale outbound, that advertises the pre-fork blocks. The node then, on its
own, requests those pre-fork blocks from the stale peer (no getblockfrompeer) and
accepts them, so its block chain advances to the pre-fork tip.
"""
from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.messages import (
    CBlock,
    CBlockHeader,
    MSG_BLOCK,
    MSG_WITNESS_FLAG,
    NODE_NETWORK,
    NODE_REDUCED_DATA,
    NODE_WITNESS,
    from_hex,
    msg_block,
    msg_headers,
)
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

FORK = 6                 # BLAKE2b activation height on regtest
POSTFORK = 3             # blake2b blocks mined past the fork
HEADLINE = "-blake2b_headline=confirm old node block download"
STALE_SERVICES = NODE_NETWORK | NODE_WITNESS | NODE_REDUCED_DATA  # no NODE_BLAKE2B


class OldPeer(P2PInterface):
    """A non-BLAKE2b peer that serves the pre-fork blocks it is asked for."""
    def __init__(self, blocks):
        super().__init__()
        self.blocks = blocks           # {int(hash): CBlock}
        self.served = set()

    def on_getdata(self, message):
        for inv in message.inv:
            if (inv.type & ~MSG_WITNESS_FLAG) == MSG_BLOCK and inv.hash in self.blocks:
                self.send_message(msg_block(self.blocks[inv.hash]))
                self.served.add(inv.hash)


class OldNodeBlockDownload(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            [f"-testactivationheight=blake2b@{FORK}", HEADLINE, "-maxstaleoutbound=2", "-connect=0"],  # node0: test
            [f"-testactivationheight=blake2b@{FORK}", HEADLINE, "-connect=0"],                          # node1: HF miner
        ]

    def setup_network(self):
        # Keep the nodes unconnected: node0's only peer is the mock stale peer.
        self.setup_nodes()

    def run_test(self):
        test, miner = self.nodes

        self.log.info("Miner builds the chain across the BLAKE2b fork")
        self.generatetoaddress(miner, FORK - 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)  # pre-fork
        self.generatetoaddress(miner, POSTFORK, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)  # blake2b
        tip_height = miner.getblockcount()

        self.log.info("Give the test node the full header chain (incl. BLAKE2b headers), no blocks")
        for h in range(1, tip_height + 1):
            test.submitheader(miner.getblockheader(miner.getblockhash(h), False))
        info = test.getblockchaininfo()
        assert_equal(info["headers"], tip_height)   # full header chain, across the fork
        assert_equal(info["blocks"], 0)             # but no block data yet

        # Pre-fork blocks the old peer holds, keyed by hash.
        prefork = {}
        for h in range(1, FORK):
            b = from_hex(CBlock(), miner.getblock(miner.getblockhash(h), 0))
            b.rehash()
            prefork[int(b.hash, 16)] = b
        prefork_tip = CBlockHeader(from_hex(CBlock(), miner.getblock(miner.getblockhash(FORK - 1), 0)))

        self.log.info("Its only peer is a stale (non-NODE_BLAKE2B) peer holding the pre-fork blocks")
        with test.assert_debug_log(["connected to stale outbound peer"]):
            peer = test.add_outbound_p2p_connection(
                OldPeer(prefork), p2p_idx=0, connection_type="outbound-full-relay",
                services=STALE_SERVICES)
        # Advertise the pre-fork tip so the node knows this peer has those blocks.
        peer.send_and_ping(msg_headers([prefork_tip]))

        self.log.info("The node downloads the pre-fork blocks from the stale peer on its own")
        self.wait_until(lambda: test.getblockcount() == FORK - 1)
        assert_equal(test.getblockcount(), FORK - 1)     # advanced to pre-fork tip via the stale peer
        assert len(peer.served) >= 1                     # blocks actually came from that peer
        self.log.info(f"Confirmed: node downloaded {len(peer.served)} pre-fork blocks from the stale peer")


if __name__ == '__main__':
    OldNodeBlockDownload(__file__).main()
