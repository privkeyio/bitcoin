# Chunked Taproot merkle path

A Taproot script-path spend proves its leaf is in the tree by handing over the merkle path from
the leaf to the root. BIP-341 puts that path in one witness item, the control block, so a path of
`m` nodes is a single field of `33 + 32m` bytes: up to 4129 for the 128 nodes BIP-341 allows.

This hardfork adds a second encoding for the same path, in which no field of path data exceeds 256
bytes. The
spending conditions do not change. The tapleaf hash, the merkle root, the output key, the address
and the signature are all identical either way; only the wire layout of the path differs.

## Why

Every byte of a merkle path is chosen by whoever funds the output: pick the sibling hashes first,
fold them into a root, then tweak the internal key by that root. Consensus cannot tell a real path
from a payload, so a flat control block is a 4 KB field of arbitrary bytes. BIP-110 rule 5 answers
that by capping the control block at 257 bytes, which caps the on-chain script tree at 128 leaves
and makes any deeper leaf unspendable while the deployment is active.

Chunking answers the same problem without the cap. The path is bounded field by field rather than
in total, so it falls under the same 256-byte ceiling as every other witness item, and no tree
depth is forbidden.

## The encoding

The flat encoding is unchanged for paths of 7 nodes or fewer, and is the only one allowed for them.
Above 7 nodes it is retired: a flat control block larger than 257 bytes is invalid once this
activates, whether or not BIP-110 is being enforced. Otherwise a deep path would have two valid
serialisations after that deployment expires, which is both the 4 KB field reopened and a witness
that a third party can rewrite without touching a signature.

An extended spend serialises the witness as:

```
[script arguments...] [leaf script] [chunk 1] ... [chunk k] [control block]
```

The control block is:

```
[1 byte: leaf version | parity] [32 bytes: internal key] [1 byte: k] [7 nodes = 224 bytes]
```

so exactly 258 bytes. The control block is the one field above the 256-byte ceiling, at 258: BIP-110
rule 5 already carves it out at 257 for the 33-byte header it must carry, and this adds one byte for
the count. Every other field, and every byte of path beyond the first seven nodes, is at or under
the ceiling. That length is also the marker, and the only one: a flat control block is
`33 + 32m` bytes, which is 1 mod 32, and an extended one is 2 mod 32, so neither can be read as
the other and no leaf version is spent to distinguish them. Nothing else in the spend changes,
which is why an output committed to an ordinary Taproot tree is spendable under this encoding
without having been created for it.

BIP-341's own upgrade hook is the leaf version, and this deliberately does not use it. The leaf
version is an input to the tapleaf hash, so it is fixed when the output is funded, and a tree
already committed with ordinary leaves could never be spent under a new one; using it would leave
exactly the coins this is meant to keep spendable behind. The length is free instead, because
BIP-341 requires the control block to be `33 + 32m` for `m` between 0 and 128 and fails every other
length, so a length of 2 mod 32 is claimed by nothing.

(BIP-110 is also published under the number 444; the rule text is the same in both.)

The path is the control block's 7 nodes, closest to the leaf, followed by the nodes of chunk 1
through chunk k, ending at the root's child. Chunk 1 sits next to the leaf script and chunk k next
to the control block.

Validity:

1. `k` is at least 1, and the witness holds at least `k` items above the leaf script.
2. Each chunk is at least one and at most eight whole 32-byte nodes, so 32 to 256 bytes. An empty
   chunk is invalid; allowing one would give every path of `7 + 8j` nodes a second encoding.
3. Every chunk except chunk k is exactly 256 bytes. Chunk k holds the remainder.
4. The total path, the control block's 7 nodes plus every chunk's, is at most 128 nodes.
5. The commitment is then checked exactly as BIP-341 checks it, folding the leaf hash with each
   node in order and comparing the tweak against the output key.

Rules 1 and 3, together with the retirement of the flat form above 7 nodes, make the encoding
canonical: a given path has exactly one valid serialisation, so the chunking itself carries no
information and cannot be used as a channel or to malleate a spend. One window is exempt. Block
timestamps are not monotonic, only greater than the parent's median time past, so around activation
blocks fall either side of the trigger and a deep path is minable flat in one and chunked in the
next. The txid is unaffected either way; the wtxid is not.
Overhead against the flat form is the count byte plus one length prefix per chunk. A 256-byte item
takes a three-byte CompactSize, so a 40-node path costs 1330 serialised bytes against the flat
form's 1316: fourteen more. Per byte of witness the chunked form is therefore fractionally the more
expensive of the two. That comparison is not the interesting one, though, and the section on
BIP-110 rule 5 below gives the one that is: against the channels this project actually relays, the
capacity per input goes up rather than down.

## Activation

Gated on `Consensus::Params::HardforkTime`, the single trigger for everything this fork carries.

Consensus compares the block's own timestamp with `>=`, matching the proof-of-work change, so every
rule the fork carries switches on at the same instant.

Policy compares the parent's median time past for the relaxing half of this rule, the one that makes
chunked spends valid that were not. A mempool keyed to the block's own timestamp would be guessing, since
the miner has not chosen that timestamp yet, and a wrong guess puts transactions in the mempool
that the next block cannot contain. Median time past is monotonic and already fixed by connected
blocks, so the mempool, the block builder and the wallet all reach the same answer in advance. A
valid block's timestamp exceeds its parent's median time past, so policy is never looser than
consensus, only later. In practice a spend using this encoding is valid in a block slightly before
it will relay.

The tapscript validation weight budget is taken from the serialised witness stack, so the chunked
form grants a slightly larger budget than the flat form of the same path. It only ever increases,
so re-serialising can never invalidate a spend, but the encoding is not weight-neutral.

The retirement of the flat form is a *restriction*, and restrictions cannot arrive at a flag day
the way relaxations can. The mempool never revalidates what it already holds, and the block
assembler throws rather than skipping an entry that has become invalid, so a deep flat witness
sitting in the mempool at activation would halt block production. `IsWitnessStandard` therefore
refuses one from the moment this code ships, unconditionally and under its own reject name, so no
such entry can exist to be stranded. `SCRIPT_VERIFY_REDUCED_DATA` already refuses the same witness,
but an `ignore_rejects` argument of `non-mandatory-script-verify-flag` drops that flag wholesale,
which is why the check does not rely on it. An operator who gives up both reject names in turn can
still seat one, and then block creation throws at activation; that is the operator asking for it,
and evicting rather than throwing is upstream behaviour in `node/miner.cpp`. The general rule, which
applies to every rule this fork carries: a relaxing half may activate late in policy, a restricting
half must activate early.

`IsWitnessStandard` and `GetScriptForTransactionInput` drop the path chunks before reading the
script and its arguments, so the standardness rules that apply per stack item, notably the 80-byte
Tapscript item limit, are not applied to chunks. `CalculateExtraTxWeight` reads the same helper, so
the extra-weight spam pricing sees the leaf script rather than a chunk as well. They do so without consulting the fork state,
which loosens nothing: a witness in this shape is invalid by consensus before activation, so any
transaction carrying one is rejected by the script checks regardless.

The whole witness stack remains subject to `-maxscriptsize`, default 1650 bytes, which is what
decides in practice how deep a relayed path may be. Chunking does not change that total.

## Relationship to BIP-110 rule 5

Path nodes are bytes the spender chooses freely, and `CScript::DatacarrierBytes` never inspects the
witness stack, so they are payload no counter sees. Lifting the depth cap enlarges that channel:
rule 5 holds it to 224 bytes per input, and afterwards the bound is `-maxscriptsize`, which at its
default of 1650 admits a 46-node path, so 1472 bytes per input. Measured against a node running
this branch, that is the cheapest bulk channel this project relays, at 3.29 payload bytes per vbyte
against 1.69 for a flat 7-node path. The aggregate per-input ceiling is `-maxscriptsize` either way
and ordinary 80-byte stack items already offer a hole of comparable size, so total block capacity
does not move, and validation cost does not follow the bytes either: 24 times the witness costs 5
times the time, since the fold is capped at 128 hashes and the node count is checked before any
hashing. Anyone weighing this change should weigh the per-input figure, and it is a further reason
to count control-block bytes in `DatacarrierBytes`, which is worth doing regardless.

Rule 5 caps the control block at 257 bytes. Under this encoding that cap becomes permanent for the
flat form and a deeper path uses the extended one, where every field is already at or under the
256-byte ceiling that rules 2 and 5 exist to enforce. The result is that the ceiling holds for every field of
path data, with the control block keeping the 33-byte header carve-out rule 5 already makes for it
and one byte more for the count; the leaf cap that rule 5 imposed as a side effect is gone; and the
ceiling no longer depends on BIP-110, which expires about a year after it activates.

## Compatibility

A node without this change rejects an extended spend, because it reads the control block as flat,
finds a length that is 2 mod 32, and fails the structural check. That is unavoidable rather than
incidental: consensus requires the fold of every path node to reproduce the output key's tweak, so
an unmodified node that folds only some prefix of the path computes a different root. No encoding
carrying more than 7 nodes can be compatible with an unmodified node, whatever it does with the
extra data, including hiding it in the annex, which is dropped before the fold. This is therefore
a hardfork change and belongs with the rest of the fork.

Nothing that only creates outputs or signs is affected:

- The tapleaf hash does not change, since the leaf version and script are untouched.
- The merkle root and so the output key and address do not change.
- Descriptors do not change.
- `SignatureHashSchnorr` commits to the tapleaf hash, the key version and the codeseparator
  position, and to the merkle root only through the spent scriptPubKey. It never commits to the
  control block or to the path. So a transaction signed before this encoding existed can be spent
  under it by re-serialising the witness, with the same signature bytes, no new signatures and no
  counterparty coordination. The txid is unchanged and only the wtxid moves.

Software that builds a spend of a path deeper than 7 nodes has to emit the new layout. That is the
whole of the tooling cost.

BIP-110's own grandfathering is not extended to this rule: `REDUCED_DATA_MANDATORY_VERIFY_FLAGS` is
cleared for inputs spending UTXOs older than that deployment, and this flag is not in that mask, so
the retirement of the flat form reaches those coins too. That is deliberate, since a carve-out would
hand exactly those coins two valid encodings, but it is the reason the paragraph below is worded as
it is.

One promise does change. BIP-110 grandfathers inputs spending UTXOs created before its activation
on the grounds that any such coin "can always be spent exactly as it could before". Retiring the
flat form above 7 nodes means a pre-signed transaction carrying a flat deep witness must have that
witness re-serialised before it will confirm. No funds are at risk, because re-serialising needs no
signature and no counterparty, but the coin is not spendable *byte for byte* as it was, and this
document says so rather than leaving the promise standing unqualified.

## Coverage

`test/functional/feature_hf_chunked_tappath.py`. It signs with the test framework's own BIP-341
code, which predates this encoding and knows nothing about it, then reuses that one signature for
every case, so a node accepting a chunked spend is an independent check that the message really is
unchanged rather than a check that two copies of new code agree.

Two properties there are worth knowing about because they are the ones the design rests on. A
40-node path refused as a flat control block while BIP-110 is active is then spent under the
chunked encoding with the identical signature bytes. And on a second node running without BIP-110
at all, the same flat path is accepted before activation and refused after it, so the single
encoding per path is this change's own doing rather than BIP-110's.

A node that was not present for any of it also syncs the whole chain over p2p and then reindexes it
from disk, so the rules hold on a fresh validator rather than only on the node that built the
blocks.

Everything else the rules above state is covered case by case: the canonical rules, the boundary at
7 and 8 nodes, depths either side of every chunk boundary, over 128 nodes, an annex, the mempool
predicate lagging consensus, the block assembler, a reorg back across activation, and a deep flat
witness refused even when the caller drops every non-mandatory script flag.
