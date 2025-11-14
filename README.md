# Art of Signature

This repository contains the source code for the protocol of the multi-party signature scheme on top of **policy trees**. 
The *policy tree* is a tree which represents an abstract syntax tree for some logical expression in the conjunctive normal form (CNF) which sets the logic for the signature scheme.

## Policy Tree Structure

Our protocol supports efficient aggregation and verification of multi-party signatures. Each node in the policy tree can be either a leaf node or an internal node. Leaf nodes contain public keys of the participants, while internal nodes represent logical gates such as `AND`, `OR`, and `NOT` (currently supported are only `AND`, `OR`). Here we present a LISP-inspired language for the policy trees, for example the policy tree for *3-of-4 threshold scheme*:

```lisp
(policy threshold_3_of_4_circuit
  (or
      (and A B C)
      (and A B D)
      (and A C D)
      (and B C D)))
```

Each node of the policy tree must be resolved before a signature session so that the every tree node will contain some public key. The *aggregated key* of a policy is the root node's public key:
- `OR` gate resolves as the Diffie-Hellman key exchange between the parties involved in the `OR` gate, public key is the scalar multiplication of the base point and the shared secret.
- `AND` gate resolves as the aggregated public key of all parties involved in the `AND` gate. We instantiate it using the *MuSig2* protocol and its public key aggregation function.
Other gates are not supported yet, but we plan to add support for them later.

## Signature and verification

We use the *MuSig2* protocol as our main instantiation for signature and verification with a signer list comprised of all clauses resolutions in the policy tree. Each clause could be resolved by some participant who is eligible to do that.
