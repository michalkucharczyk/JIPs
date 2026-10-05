# JIP-6: Compact state proofs

A compact Merkle proof for the JAM state trie, proving the values of some state keys and the absence
of others against a trusted state root.

## Motivation

A client that trusts a block's state root may need to verify a small set of state values without
trusting the server that provides them. Existing whole-node proofs, such as the CE 129 range proof,
work well for state synchronisation but are inefficient for a few unrelated keys: they ship
redundant branch data, repeat common trie paths across requests, and require rebuilding a partial
trie during verification.

The proof defined here is designed for this smaller, selective access pattern.  It includes only the
missing child identity at each branch, supports multiple keys and ranges in one proof, proves both
presence and absence, and can omit keys or values already known to the client. It is verified in a
single pass with a stack and is typically much smaller than a whole-node range proof for small
queries.

The proof format is independent of its transport and may be used by any protocol.

## Proof subtree

Throughout this document two terms are used:

- The path to a node is the sequence of bits walked from the root to reach it.
- The node's depth is the length of that path.

A proof subtree is built from a set of trie nodes, called expanded nodes, that contains the root
and, for every other node, its parent. It consists of those nodes and both children of each expanded
branch. Each node is represented as one of:

- `B`: an expanded branch, followed by its left child and then its right child.
- `L`: an expanded leaf.
- `E`: an empty subtree.
- `H`: a node that is neither expanded nor empty, given by its identity.

A proof subtree proves:

- for every `L` it contains, the leaf's key and entry, where the entry is either a value or a value
  hash;
- the absence of every key whose path:
  - reaches an `E` at any depth, or
  - ends at an `L` holding a different key.

It proves nothing about a key whose path reaches an `H`. Two degenerate subtrees exist: a single `E`
for an empty state, and a single `H` carrying the state root when nothing is expanded.

Which nodes a server expands for a given request is defined under [Queries](#queries).

## Encoding

The decoded data of a State Proof consists of a version octet followed by five sections, with no
lengths:

```
proof   = version tags kinds hashes keys values
version = 0x00
tags    = subtree, then zero bits up to the next octet boundary
subtree = B subtree subtree | H | E | L
kinds   = one 2-bit kind per L, in tag order, then zero bits up to the next octet boundary
hashes  = 32 octets per H and per ValueHash leaf, in tag order
keys    = key suffix bits per leaf whose kind ships a key, in tag order,
          then zero bits up to the next octet boundary
values  = value's len, then the value, per leaf whose kind ships a value, in tag order
```

The `version` octet identifies the encoding defined here, version 0; later revisions of this
document may define further versions.

The `tags` section lists the nodes of the proof subtree in pre-order traversal: a `B` is followed by
the tags of its left subtree and then those of its right subtree. This order is called tag order,
and the other sections follow it.

Each tag is two bits: `B` is `00`, `H` is `01`, `E` is `10` and `L` is `11`. Tags are packed from
the most significant bits of each octet down, so the first tag occupies bits 7 and 6 of the first
octet of the `tags` section.

The `tags` section ends when the subtree is complete. It starts with one subtree open. Each `H`, `L`
or `E` tag closes one, while each `B` closes one and opens two more. The section ends when none
remain open. 

The later sections carry no lengths either: the tags and kinds determine how much each of `hashes`
and `keys` holds, as described below, and `values` takes the remainder.

The `kinds` section holds one 2-bit kind per `L` tag, in tag order, packed like the tags and padded
with zero bits to an octet boundary. The kind says what the proof ships for the leaf:

| Kind | Code | Key | Value |
|---|---|---|---|
| `Full` | `00` | suffix in `keys` | `len` and value in `values` |
| `ValueHash` | `01` | suffix in `keys` | hash in `hashes` |
| `KeyElided` | `10` | from the client | `len` and value in `values` |
| `FullyElided` | `11` | from the client | from the client |

`len` is the value's length, encoded as per the GP's variable-length serialization of natural
numbers, and is less than $2^{32}$. A value of at most 32 octets gives an embedded leaf node, a
longer one a leaf node with the value's hash, as per the GP. 

A `ValueHash` leaf ships the hash of its value instead of the value itself, and the leaf node is
rebuilt from that hash.  When a server uses this kind is defined under [Queries](#queries).

The `hashes` section is a sequence of 32-octet entries, one per `H` tag and one per `ValueHash`
leaf, in tag order. The entry for an `H` is the identity of the node it stands for. If that node is
a left child, its identity is encoded as in its parent: with the most significant bit (bit 7 of
octet 0) cleared. The entry for a `ValueHash` leaf is the hash of its value, and takes its place in
the sequence at the position of the leaf's `L` tag.

The `keys` section holds, for each leaf whose kind ships a key, in tag order, the last $248 - d$
bits of its key, $d$ being the leaf's depth and the first $d$ bits being the path to it. These
suffixes are concatenated, most significant bit first, without padding between them. The section is
padded with zero bits to an octet boundary at its end only. The leaf's key is the path to it
followed by its suffix.

The `values` section holds, for each leaf whose kind ships a value, in tag order, `len` and then the
value.

## Canonical form

A verifier must reject a proof if any of the following holds:

1. The version octet is not 0.
2. The proof is empty, or the `tags` section ends before the subtree is complete.
3. A padding bit of the `tags` section is set.
4. A `B` is at depth 248 or deeper.
5. A `B` has two `H` children, two `E` children, or an `E` and an `L` child in either order. A `B`
   with an `H` and an `E` child is valid: it is how the path of an absent listed key ends at an
   empty child beside an unexpanded sibling.
6. An `H` carries the zero hash, or an `H` which is a left child has the most significant bit of
   its identity set.
7. A padding bit of the `kinds` section is set.
8. A `len` is $2^{32}$ or more, or is not the octets the GP's encoding gives for that number (e.g.
   `80 28` in place of `28` for 40).
9. A padding bit of the `keys` section is set.
10. For a key-elided or fully elided leaf, the client's known keys contain no key, or more than one
    key, starting with the path to the leaf.
11. A section is shorter than its contents require, or octets remain after the value data of the
    last leaf.
12. The identity of the root of the proof subtree differs from the trusted state root.

These rules give every proof subtree, with a given kind for each leaf, exactly one encoding. The
verifier accepts any canonically encoded proof subtree whose root identity is the state root.

It checks neither that the subtree is minimal for the query nor that the leaf kinds conform to the
query. A proof may therefore expand more of the trie than the query needs, which proves more keys,
never fewer. The subtree and kinds a server produces are defined under [Queries](#queries).

A client may bound the size of the proofs it accepts.

## Verification

The verifier takes the proof and a trusted state root. If any leaf is elided, it also takes the
client's known keys with their values. While reading the tags in order it keeps the path to the
current node and a stack of open branches, those whose right child is still to come.

Reading a `B` opens a branch: an entry is pushed and the left child is read next. When a node
completes and the top entry is still empty, the node is the left child: its identity and tag are
stored in the entry, and the right child is read next. When a node completes and the top entry
already holds a left child, the node is the right child: the branch's identity is computed from the
two, the entry is popped, and the branch is itself a completed node, to be handled the same way by
the entry below. The proof is valid when the final completed node is the root of the proof subtree
and its identity equals the state root:

    stack = empty, path = empty
    loop:
        tag = next tag
        match tag:
            B: push an empty entry; append 0 to path; continue
            H: id = next hash
            E: id = zero hash; path is covered
            L: (key, entry) = next leaf at path; id = identity of the leaf
               key is present with entry; path is covered
        loop:
            if stack is empty:
                require id = state root; done
            if top of stack is empty:
                top of stack = (tag, id); set the last bit of path to 1; break
            (left tag, left) = pop stack; remove the last bit of path
            check rule 5 on (left tag, tag)
            id = identity of the branch with children left and id; tag = B

The pseudo-code omits the other canonical-form rules, which are checked as each tag, leaf and branch
is read or completed. To read a leaf, the verifier takes the next kind and then, by kind:

- `Full`: the key is the path followed by the next $248 - d$ bits of the `keys` section, $d$ being
  the length of the path; the entry is the next `len` and value from the `values` section;
- `ValueHash`: the key as for `Full`; the entry is the next hash from the `hashes` section;
- `KeyElided`: the key is the single known key starting with the path; the entry as for `Full`, and
  any known value is ignored;
- `FullyElided`: the key is the single known key starting with the path, and the entry is its known
  value.

The result is the set of present keys with their entries, each either a value or a value hash,
and the set of covered paths. A key is then:

- Present, if it is a present key.
- Absent, if it is not present and a covered path is a prefix of it: its path in the proof
  subtree ends at an `E` or at an `L` holding a different key.
- Not covered, otherwise: its path leaves the proof subtree through an `H`.

A client must treat a key that is not covered as a failed proof, never as an absent key. For a
listed key this is the outcome of looking it up. For a range, the client cannot individually look up
keys it does not know. It must therefore check that no `H` stands for a node whose path is a prefix
of a key within the range. Such an `H` could hide keys of the range, which would then be neither
present nor absent in the result.

## Queries

A query consists of:

- Listed keys: a strictly ascending sequence of State Keys.
- Ranges: pairs `[start, end]` of prefix bounds, each 0 to 31 octets long. The range contains
  every key from `start` padded to 31 octets with `0x00` up to `end` padded to 31 octets with
  `0xFF`, both inclusive; `[p, p]` is thus every key starting with `p`, and `[empty, empty]` is
  the whole state.
- Known mode: one of `none`, `keys` and `keys_and_values`. `keys` declares that the client
  already holds every listed key that is in the state and every key of the state within a range;
  `keys_and_values` declares that it holds these keys with their values. The server does not
  check the declaration.

After padding, each range's `start` must not exceed its `end`, each range's `start` must exceed the
previous range's `end`, and no listed key may lie within a range.

The proof subtree for a query expands a node if a listed key starts with the path to it, or if a key
starting with the path to it lies within a listed range. It follows that:

- the root is expanded whenever the query has a listed key or a range;
- a listed key that is not in the state has a path ending at an `E`, or at an `L` holding a
  different key;
- for a state with a single key, any non-empty query gives a single `L`;
- an empty query gives a single `H` carrying the state root.

A leaf is eligible for elision if its key is a listed key or lies within a range, and no other
listed key starts with the path to it. The second condition is there because the verifier identifies
an elided leaf by the one known key that starts with the path to it, as described under
[Verification](#verification). That identification is ambiguous in one situation: a listed key that
is absent from the state, whose walk ends at the leaf of another listed key. Both keys then start
with that leaf's path, so that leaf is not eligible and stays full. The listed keys meant here are
those of the request as sent; a key the cut drops is still among the client's known keys.

A leaf's kind follows from its eligibility and the `known` mode. An eligible leaf is `Full` under
`none`, `KeyElided` under `keys` and `FullyElided` under `keys_and_values`. A leaf that is not
eligible is `Full` whatever the mode.

There is one exception. A leaf whose key is neither a listed key nor within a range is in the proof
only because a listed key's path ends at it, or because a key within a range starts with the path to
it while its own key lies outside every range. Its value was not asked for, so when that value is
longer than 32 octets the leaf is `ValueHash` and ships the value's hash instead. A shorter value is
shipped as it is, since the leaf node contains it.

The charged keys of a query are its listed keys and the keys of the state that lie within its
ranges. Since the listed keys are sorted, the ranges are sorted and disjoint, and no listed key lies
within a range, the charged keys form one ascending sequence. A range containing no key of the state
adds no charged keys. The size limit applies to this sequence.

The charge for a charged key is the size of the leaf at which its lookup ends. For an absent listed
key, that leaf holds a different key. A listed key whose lookup ends at an empty subtree is charged
nothing. A leaf's charged size is:

- 1, for its kind;
- $\lceil (248 - d) / 8 \rceil$ if its key suffix is shipped;
- the length of its `len` and value in the `values` section, or 32 for a ValueHash leaf.

The charge is computed per leaf and is deliberately conservative: key suffixes are packed without
per-leaf padding, so the charged total may exceed the octets the leaves actually add.

The server includes charged keys in order while their total charge stays within the limit; the first
charged key is always included. If a charged key does not fit, the server stops there: `"complete"`
is False and `"proven_through"` is the last charged key included. If every charged key fits,
`"complete"` is True.

The query cut at a key $k$ is a shorter query derived from the request: it keeps the listed keys
that do not exceed $k$, removes every range whose padded `start` exceeds $k$, and ends every
remaining range whose padded `end` exceeds $k$ at $k$. A truncated reply is not a special form of
proof: it carries the proof subtree of the query cut at `"proven_through"`, and the client verifies
it as such. Whether a leaf's key counts as listed or within a range follows the cut query; only the
shared-prefix condition on eligibility counts the listed keys of the request as sent.

A client receiving a truncated reply must verify it against the query cut at `"proven_through"`, and
may continue with the remaining listed keys and the ranges cut to start after it.

The cut cannot be inferred from the proof: a truncated proof may still cover the whole query, as an
absent listed key can expand the region the cut removed. `"complete"` and `"proven_through"` are
authoritative.

## Test vectors

These vectors use a state of five keys, named by their first three bits: `000`, `001`, `100`, `110`
and `111`. Octet 0 of each key is those three bits followed by `11010`, and octets 1 to 30 are
`0x5A`; key `110` is thus `0xDA` followed by thirty `0x5A` octets. The value under each key is the
nine octets of the ASCII string `value ` followed by the key's three bits, e.g. `value 110`. The
state root is `9b9760b1a0bbb685177ad5ddd98b1ae446307255aca511c22e4c2e778cec425f`.

The identities used below, as they appear in the `hashes` section, are those of the leaves holding
keys `000`, `100`, `110` and `111`, and of the subtrees under the prefixes `0` (keys `000` and
`001`), `00` (the same two keys) and `11` (keys `110` and `111`):

    leaf 000     40f3854ff47a42a159d21e8275e15df4937d19063426e38cfdc30878dbc22ea6
    leaf 100     6b177808b75d08e8e68fc330d42ebdda1eadbd804db18d1e4679cbcb349c52df
    leaf 110     2af306b851cf153d7c58cf43682fed3b75f2cdd7dfc9a547dcfe990ccaea77ab
    leaf 111     883a0c1f05cbac875dae2e53c5c15dfad106d7272bf3cb07015aae7e8656f7f9
    subtree 0    50918ec4ad4465ee3baa8a272129bd2534ad911f63d22abff4716baa78bc97c3
    subtree 00   41dd8fddabce96f7a9e0b737297a41b55924bb4e5e7c7e2f0772ef948a60debd
    subtree 11   4edb3501f7717e134d548ba9825c4e98a8fe174ec15b2d51667d3688dca3f7e9

Each proof is shown in hex, with its version octet, tags, kinds, hashes, keys and values separated
by `|`.

- Key `110`, known mode `none`:

      0011340050918ec4ad4465ee3baa8a272129bd2534ad911f63d22abff4716baa78bc97c36b177808b75d08e8e68fc330d42ebdda1eadbd804db18d1e4679cbcb349c52df883a0c1f05cbac875dae2e53c5c15dfad106d7272bf3cb07015aae7e8656f7f9d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d00976616c756520313130

  `00` | `1134` = `B H B H B L H` and 2 padding bits | `00` = Full and 6 padding bits | subtree 0,
  leaf 100, leaf 111 | key `110` at depth 3: 245 bits and 3 padding bits = 31 octets | `09` `value
  110`

- Keys `001` and `111`, known mode `none`:

      0001e11c0040f3854ff47a42a159d21e8275e15df4937d19063426e38cfdc30878dbc22ea66b177808b75d08e8e68fc330d42ebdda1eadbd804db18d1e4679cbcb349c52df2af306b851cf153d7c58cf43682fed3b75f2cdd7dfc9a547dcfe990ccaea77abd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d6969696969696969696969696969696969696969696969696969696969696800976616c7565203030310976616c756520313131

  `00` | `01e11c` = `B B B H L E B H B H L` and 2 padding bits | `00` = Full, Full and 4 padding
  bits | leaf 000, leaf 100, leaf 110 | keys `001` and `111` at depth 3: 245 + 245 bits and 6
  padding bits = 62 octets | `09` `value 001`, `09` `value 111`

- Keys `001` and `111`, known mode `keys`, verified with known keys `001` and `111`:

      0001e11ca040f3854ff47a42a159d21e8275e15df4937d19063426e38cfdc30878dbc22ea66b177808b75d08e8e68fc330d42ebdda1eadbd804db18d1e4679cbcb349c52df2af306b851cf153d7c58cf43682fed3b75f2cdd7dfc9a547dcfe990ccaea77ab0976616c7565203030310976616c756520313131

  `00` | `01e11c` as above | `a0` = KeyElided, KeyElided and 4 padding bits | leaf 000, leaf 100,
  leaf 110 | none | `09` `value 001`, `09` `value 111`

- Range `[001, 110]`, known mode `none`:

      0001e3340040f3854ff47a42a159d21e8275e15df4937d19063426e38cfdc30878dbc22ea6883a0c1f05cbac875dae2e53c5c15dfad106d7272bf3cb07015aae7e8656f7f9d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d34b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0976616c7565203030310976616c7565203130300976616c756520313130

  `00` | `01e334` = `B B B H L E B L B L H` and 2 padding bits | `00` = Full ×3 and 2 padding bits |
  leaf 000, leaf 111 | keys `001` (depth 3), `100` (depth 2), `110` (depth 3): 245 + 246 + 245 bits
  = 92 octets | `09` `value 001`, `09` `value 100`, `09` `value 110`

- Keys `010` and `101`, both absent, known mode `none`:

      0006340041dd8fddabce96f7a9e0b737297a41b55924bb4e5e7c7e2f0772ef948a60debd4edb3501f7717e134d548ba9825c4e98a8fe174ec15b2d51667d3688dca3f7e9696969696969696969696969696969696969696969696969696969696969680976616c756520313030

  `00` | `0634` = `B B H E B L H` and 2 padding bits | `00` = Full and 6 padding bits | subtree 00,
  subtree 11 | key `100` at depth 2: 246 bits and 2 padding bits = 31 octets; the leaf is shipped
  because the walk for `101` ends at it | `09` `value 100`

- The empty state, any query:

      0080

  `00` | `80` = `E` and 6 padding bits | none | none | none | none

- A state holding only `110`, key `110`:

      00c000da5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a0976616c756520313130

  `00` | `c0` = `L` and 6 padding bits | `00` = Full and 6 padding bits | none | key `110` at depth
  0: all 248 bits = 31 octets | `09` `value 110`
