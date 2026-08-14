#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the hardfork's chunked Taproot merkle path encoding.

A path deeper than 7 nodes arrives in chunks of at most 256 bytes, carried
between the leaf script and a control block whose size is 2 mod 32. That size
is invalid for a flat control block, so the encoding identifies itself without
spending a leaf version, and the tapleaf hash, the merkle root and the output
key are all untouched.

The claim the design rests on is that the signature does not cover the path:
SignatureHashSchnorr commits to the tapleaf hash, not to the control block. So
a spend signed before this encoding existed is spendable under it by
re-serializing, with the same signature bytes. This test signs with the test
framework's own BIP-341 code, which knows nothing about chunking, and reuses
that one signature for every encoding below.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.blocktools import add_witness_commitment, create_block, create_coinbase
from test_framework.key import compute_xonly_pubkey, generate_privkey, sign_schnorr
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    OP_CHECKSIG,
    OP_0,
    TaprootSignatureHash,
    taproot_construct,
)
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

HARDFORK_TIME = 1788220800  # 2026-09-01
# submitblock's reason for every shape this test gets wrong, so a rejection cannot pass
# vacuously on some unrelated block-level failure.
BAD_CONTROL = "mandatory-script-verify-flag-failed (Invalid Taproot control block size)"
FLAT_NODES = 7              # nodes the extended control block carries itself
CHUNK_NODES = 8             # nodes in a full chunk (256 bytes)


class ChunkedTappathTest(BitcoinTestFramework):
    def set_test_params(self):
        # Node 1 runs without BIP-110, so what it refuses is this encoding's own doing.
        # Node 2 stays offline until the end, then validates the whole chain from scratch.
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.extra_args = [
            [f'-hardforktime={HARDFORK_TIME}', '-vbparams=reduced_data:-1:999999999999:0',
             '-corepolicy=0'],
            [f'-hardforktime={HARDFORK_TIME}'],
            [f'-hardforktime={HARDFORK_TIME}', '-vbparams=reduced_data:-1:999999999999:0'],
        ]

    def setup_network(self):
        self.setup_nodes()

    def deep_output(self, depth, payload):
        """A Taproot output committing to a CHECKSIG leaf `depth` levels down."""
        leaf_key = generate_privkey()
        leaf_pubkey, _ = compute_xonly_pubkey(leaf_key)
        internal_key = generate_privkey()
        internal_pubkey, _ = compute_xonly_pubkey(internal_key)
        script = CScript([leaf_pubkey, OP_CHECKSIG])
        tree = ("leaf", script)
        for i in range(depth):
            tree = [tree, (lambda n: (lambda h: n))(payload[i * 32:(i + 1) * 32])]
        info = taproot_construct(internal_pubkey, [tree])
        leaf = info.leaves["leaf"]
        control = bytes([leaf.version + info.negflag]) + internal_pubkey + leaf.merklebranch
        assert_equal(len(control), 33 + 32 * depth)
        return info, script, control, leaf_key

    def signed_spend(self, depth, idx=0, annex=None):
        """Fund a `depth`-deep output and sign a spend of its leaf, flat-form agnostic."""
        node = self.nodes[idx]
        payload = bytes(str(depth).encode()) + b"x" * (32 * depth)
        info, script, control, leaf_key = self.deep_output(depth, payload)
        funded = self.wallets[idx].send_to(from_node=node, scriptPubKey=info.scriptPubKey, amount=100000)
        self.generate(self.wallets[idx], 1, sync_fun=self.no_op)
        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(funded["txid"], 16), funded["sent_vout"]), nSequence=0)]
        tx.vout = [CTxOut(100000 - 1000, CScript([OP_0, bytes(20)]))]
        tx.wit.vtxinwit.append(CTxInWitness())
        spent = [CTxOut(100000, info.scriptPubKey)]
        msg = TaprootSignatureHash(tx, spent, 0, input_index=0, scriptpath=True, leaf_script=script, annex=annex)
        sig = sign_schnorr(leaf_key, msg)
        tx.rehash()
        return tx, script, control, sig

    @staticmethod
    def chunked(control, script, sig, *, count=None, chunks=None):
        """Witness stack for the extended encoding: [sig] [script] [chunks...] [control]."""
        path = control[33:]
        head, rest = path[:FLAT_NODES * 32], path[FLAT_NODES * 32:]
        full = CHUNK_NODES * 32
        if chunks is None:
            chunks = [rest[i:i + full] for i in range(0, len(rest), full)]
        if count is None:
            count = len(chunks)
        return [sig, script, *chunks, control[:33] + bytes([count]) + head]

    def submit(self, tx, witness, block_time, idx=0):
        """Mine `tx` alone in a block. Returns submitblock's reason, or None when accepted."""
        node = self.nodes[idx]
        tx.wit.vtxinwit[0].scriptWitness.stack = witness
        tip = node.getbestblockhash()
        block = create_block(int(tip, 16), create_coinbase(node.getblockcount() + 1), block_time)
        block.vtx.append(tx)
        add_witness_commitment(block)
        block.solve()
        reason = node.submitblock(block.serialize().hex())
        accepted = node.getbestblockhash() == block.hash
        assert_equal(accepted, reason is None)
        return reason

    def run_test(self):
        node = self.nodes[0]
        self.wallets = [MiniWallet(n) for n in self.nodes[:2]]
        for wallet in self.wallets:
            self.generate(wallet, 200, sync_fun=self.no_op)

        depth = 40
        tx, script, control, sig = self.signed_spend(depth)
        before = int(node.getblockheader(node.getbestblockhash())["time"]) + 1
        assert before < HARDFORK_TIME

        self.log.info("A flat control block deeper than 7 nodes is frozen by RDTS rule 5")
        assert_equal(self.submit(tx, [sig, script, control], before), BAD_CONTROL)

        self.log.info("The chunked encoding is not available before the hardfork either")
        assert_equal(self.submit(tx, self.chunked(control, script, sig), before), BAD_CONTROL)

        node.setmocktime(HARDFORK_TIME + 600)
        after = HARDFORK_TIME + 600

        self.log.info("Malformed chunkings are rejected after activation")
        path = control[33:][FLAT_NODES * 32:]
        full = CHUNK_NODES * 32
        good = [path[i:i + full] for i in range(0, len(path), full)]
        cases = {
            "no chunks at all": dict(count=0, chunks=[]),
            # +2 leaves fewer items than the count claims, which is the only guard between an
            # attacker-chosen count and that many unchecked pops.
            "a count larger than the stack": dict(count=len(good) + 2),
            "a count that eats the leaf script": dict(count=len(good) + 1),
            "a short chunk before the last": dict(chunks=[good[0][:32], *good[1:]]),
            "an oversized chunk": dict(chunks=[good[0] + good[1][:32], *good[1:]]),
            "a chunk that is not whole nodes": dict(chunks=[good[0][:-1], *good[1:]]),
            "an empty last chunk": dict(chunks=[*good, b""]),
        }
        for name, kwargs in cases.items():
            assert_equal(self.submit(tx, self.chunked(control, script, sig, **kwargs), after), BAD_CONTROL)
            self.log.info(f"  rejected: {name}")

        self.log.info("The same signature spends the same coin once re-serialized")
        pre_fork_tip = node.getbestblockhash()
        witness = self.chunked(control, script, sig)
        assert_equal(witness[0], sig)
        assert_equal(len(witness[-1]), 34 + 32 * FLAT_NODES)
        assert all(len(c) <= 256 for c in witness[2:-1])
        assert_equal(self.submit(tx, witness, after), None)
        first_fork_block = node.getbestblockhash()
        confirmed = node.getrawtransaction(tx.hash, True, first_fork_block)
        assert_equal(confirmed["vin"][0]["txinwitness"][0], sig.hex())
        self.log.info(f"  spent at height {node.getblockcount()}, path of {depth} nodes in "
                      f"{len(witness) - 3} chunks, no field over 256 bytes")

        self.log.info("A path of 7 nodes or fewer still uses the flat encoding")
        shallow_tx, shallow_script, shallow_control, shallow_sig = self.signed_spend(3)
        assert_equal(self.submit(shallow_tx, [shallow_sig, shallow_script, shallow_control], after + 1), None)

        self.log.info("A path over 128 nodes is still refused")
        deep_tx, deep_script, deep_control, deep_sig = self.signed_spend(129)
        assert_equal(self.submit(deep_tx, self.chunked(deep_control, deep_script, deep_sig), after + 2), BAD_CONTROL)

        self.log.info("The mempool follows the parent median time past, not the block's own clock")
        relay_tx, relay_script, relay_control, relay_sig = self.signed_spend(depth)
        relay_tx.wit.vtxinwit[0].scriptWitness.stack = self.chunked(relay_control, relay_script, relay_sig)
        res = node.testmempoolaccept([relay_tx.serialize().hex()])[0]
        assert_equal(res["allowed"], False)
        self.log.info(f"  before the median crosses: {res['reject-reason']}")
        self.generate(self.wallets[0], 12, sync_fun=self.no_op)
        res = node.testmempoolaccept([relay_tx.serialize().hex()])[0]
        assert_equal(res["allowed"], True)
        self.log.info(f"  after: relayed, {res['vsize']} vB")

        self.log.info("The node's own block assembler mines it, rather than the mempool holding what a block cannot")
        relay_txid = node.sendrawtransaction(relay_tx.serialize().hex())
        mined = self.generate(self.wallets[0], 1, sync_fun=self.no_op)[0]
        assert relay_txid in node.getblock(mined)["tx"]
        self.log.info(f"  mined at height {node.getblockcount()} by getblocktemplate, not by hand")

        self.log.info("A reorg back across activation drops the entry instead of stranding it")
        node.invalidateblock(mined)
        assert relay_txid in node.getrawmempool()
        node.invalidateblock(first_fork_block)
        assert_equal(node.getbestblockhash(), pre_fork_tip)
        assert relay_txid not in node.getrawmempool()
        assert tx.hash not in node.getrawmempool()
        self.log.info("  both chunked spends dropped from the mempool on the way back")
        node.reconsiderblock(first_fork_block)

        self.log.info("A deep flat witness cannot be seated in the mempool to be stranded at activation")
        strand_tx, strand_script, strand_control, strand_sig = self.signed_spend(depth, idx=1)
        strand_tx.wit.vtxinwit[0].scriptWitness.stack = [strand_sig, strand_script, strand_control]
        strand_hex = strand_tx.serialize().hex()
        # Node 1 runs without BIP-110, and this argument drops every non-mandatory script flag,
        # so nothing but the named standardness check stands between this and the mempool.
        res = self.nodes[1].testmempoolaccept([strand_hex], 0, ["non-mandatory-script-verify-flag"])[0]
        assert_equal(res["allowed"], False)
        assert_equal(res["reject-reason"], "bad-witness-taproot-control-size")
        self.log.info(f"  refused even with script flags dropped: {res['reject-reason']}")

        self.log.info("With BIP-110 absent, the flat encoding still gives up the paths it cannot hold")
        plain_tx, plain_script, plain_control, plain_sig = self.signed_spend(depth, idx=1)
        plain_before = int(self.nodes[1].getblockheader(self.nodes[1].getbestblockhash())["time"]) + 1
        assert plain_before < HARDFORK_TIME
        assert_equal(self.submit(plain_tx, [plain_sig, plain_script, plain_control], plain_before, idx=1), None)
        self.log.info("  before the fork: the flat form is the only one, and it is accepted")
        chunk_tx, chunk_script, chunk_control, chunk_sig = self.signed_spend(depth, idx=1)
        self.nodes[1].setmocktime(HARDFORK_TIME + 600)
        assert_equal(self.submit(chunk_tx, [chunk_sig, chunk_script, chunk_control], after, idx=1), BAD_CONTROL)
        self.log.info("  after the fork: the same flat form is refused, so a path has one encoding")
        assert_equal(self.submit(chunk_tx, self.chunked(chunk_control, chunk_script, chunk_sig), after, idx=1), None)
        self.log.info("  after the fork: the chunked form spends it")

        self.log.info("An annex sits above the chunks and is dropped before them")
        annex = bytes([ANNEX_TAG]) + b"annex"
        annex_tx, annex_script, annex_control, annex_sig = self.signed_spend(depth, idx=1, annex=annex)
        assert_equal(self.submit(annex_tx, self.chunked(annex_control, annex_script, annex_sig) + [annex],
                                 after + 1, idx=1), None)

        self.log.info("A node that was not here for any of it validates the chain from scratch")
        self.nodes[2].setmocktime(after + 3600)
        self.connect_nodes(0, 2)
        self.sync_blocks([self.nodes[0], self.nodes[2]], timeout=180)
        assert_equal(self.nodes[2].getbestblockhash(), node.getbestblockhash())
        assert tx.hash in self.nodes[2].getblock(first_fork_block)["tx"]
        self.log.info(f"  synced {self.nodes[2].getblockcount()} blocks over p2p, chunked spends and all")

        self.log.info("And a reindex revalidates every one of them from disk")
        self.restart_node(2, extra_args=self.extra_args[2] + [f"-mocktime={after + 3600}", "-reindex"])
        assert_equal(self.nodes[2].getbestblockhash(), node.getbestblockhash())
        assert tx.hash in self.nodes[2].getblock(first_fork_block)["tx"]
        self.log.info(f"  reindexed to height {self.nodes[2].getblockcount()}")

        self.log.info("Every depth from the boundary up encodes and spends")
        for d in (8, 9, 15, 16, 23, 24, 128):
            d_tx, d_script, d_control, d_sig = self.signed_spend(d, idx=1)
            wit = self.chunked(d_control, d_script, d_sig)
            chunks = wit[2:-1]
            assert_equal(sum(len(c) for c in chunks) + FLAT_NODES * 32, 32 * d)
            assert all(len(c) == CHUNK_NODES * 32 for c in chunks[:-1])
            assert_equal(self.submit(d_tx, wit, after + 2 + d, idx=1), None)
        self.log.info("  depths 8, 9, 15, 16, 23, 24 and 128 each spent under one canonical encoding")


if __name__ == "__main__":
    ChunkedTappathTest(__file__).main()
