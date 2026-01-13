# BLISK

This repository contains the source code for the protocol of the multi-party signature scheme on top of **policy trees** called BLISK (Boolean circuit Logic Compiled into Single Key). 
The *policy tree* is a tree which represents an abstract syntax tree for some logical expression in the conjunctive normal form (CNF) which sets the logic for the signature scheme.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Policy Language](#policy-language)
  - [Basic Syntax](#basic-syntax)
  - [Supported Operators](#supported-operators)
  - [Examples](#examples)
- [How-To Guide](#how-to-guide)
  - [Step 1: Write a Policy](#step-1-write-a-policy)
  - [Step 2: Compile the Policy](#step-2-compile-the-policy)
  - [Step 3: Resolve the Policy Tree](#step-3-resolve-the-policy-tree)
  - [Step 4: Create Signers](#step-4-create-signers)
  - [Step 5: Run the Signature Protocol](#step-5-run-the-signature-protocol)
  - [Step 6: Verify the Signature](#step-6-verify-the-signature)
- [Complete Example](#complete-example)
- [Policy Tree Structure](#policy-tree-structure)
- [API Reference](#api-reference)

## Overview

BLISK enables multi-party threshold signatures with flexible access policies. Instead of simple "k-of-n" schemes, you can express complex boolean logic like "Alice AND (Bob OR Charlie)" to define who can sign.

Key features:
- **Flexible policies**: Express complex signing conditions using AND/OR/Threshold logic
- **Native threshold support**: Use `(threshold k ...)` syntax for k-of-n schemes with automatic CNF optimization
- **MuSig2-based**: Uses the MuSig2 protocol for secure signature aggregation
- **CNF optimization**: Automatically transforms policies to Conjunctive Normal Form for efficient processing
- **Single aggregated key**: The entire policy compiles down to a single public key for verification

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
art-of-signature = { git = "https://github.com/zero-art-rs/blisk.git" }
```

## Policy Language

### Basic Syntax

Policies are written in a LISP-inspired S-expression format:

```lisp
(policy <name> <expression>)
```

### Supported Operators

| Operator | Syntax | Description |
|----------|--------|-------------|
| Key | `A`, `Bob`, `alice_key` | A participant's identifier (alphanumeric + underscore/hyphen) |
| AND | `(and A B C ...)` | All participants must sign |
| OR | `(or A B C ...)` | At least one participant must sign |
| Threshold | `(threshold k A B C ...)` | At least k of the n participants must sign |

### Examples

**Simple AND (all must sign):**
```lisp
(policy multisig_2_of_2 (and Alice Bob))
```

**Simple OR (any can sign):**
```lisp
(policy backup_key (or primary_key backup_key))
```

**2-of-3 Threshold (using threshold operator):**
```lisp
(policy threshold_2_of_3 (threshold 2 A B C))
```

**3-of-4 Threshold (using threshold operator):**
```lisp
(policy threshold_3_of_4 (threshold 3 A B C D))
```

**Equivalent manual expansion (for reference):**
```lisp
;; 2-of-3 manually expanded:
(policy threshold_2_of_3_manual
  (or
    (and A B)
    (and A C)
    (and B C)))

;; 3-of-4 manually expanded:
(policy threshold_3_of_4_manual
  (or
    (and A B C)
    (and A B D)
    (and A C D)
    (and B C D)))
```

**Complex nested policy:**
```lisp
(policy corporate_wallet
  (and
    (or CEO CFO)
    (or legal_dept compliance_dept)
    treasury))
```

**Threshold with nested expressions:**
```lisp
(policy complex_threshold
  (threshold 2
    (and A B)      ; Sub-policy 1: both A and B
    (or C D)       ; Sub-policy 2: either C or D  
    E))            ; Sub-policy 3: just E
```

**11-of-15 Multisig (efficiently compiled to CNF):**
```lisp
(policy multisig_11_of_15
  (threshold 11 A B C D E F G H I J K L M N O))
```

## How-To Guide

### Step 1: Write a Policy

Define your signing policy as a string:

```rust
let policy_str = "(policy my_policy (and (or A B) (or C D)))";
```

### Step 2: Compile the Policy

Parse and compile the policy with participant public keys:

```rust
use art_of_signature::parser::parse;
use art_of_signature::compiler::{Compiler, CompilationOptions};
use art_of_signature::musig2::{self, DefaultMuSig2Hash};
use ark_secp256k1::{Affine as G1Affine, Fr};
use ark_ff::{BigInteger, PrimeField};

// Parse the policy expression
let (_, expr) = parse(policy_str).unwrap();

// Generate random keys for testing (in production, use real keys)
let test_keys = expr.generate_random_keys::<G1Affine>().unwrap();

// Extract public keys into a HashMap
let public_keys = test_keys
    .iter()
    .map(|(k, (_, pk))| (k.clone(), *pk))
    .collect();

// Set up compilation options
let options = CompilationOptions {
    public_keys,
    transform_to_cnf: true,  // Transform to CNF for efficient signing
    aggregate: |points| {
        musig2::aggregate_public_keys(&points, &DefaultMuSig2Hash::new()).unwrap()
    },
    iota: |P: G1Affine| {
        Fr::from_le_bytes_mod_order(&P.x().unwrap().into_bigint().to_bytes_le())
    },
};

// Compile the policy
let compiler = Compiler::new();
let policy = compiler.compile(&expr, options).unwrap();
```

### Step 3: Resolve the Policy Tree

Before signing, participants must resolve the policy tree with their private keys. This computes the derived keys for OR gates using Diffie-Hellman:

```rust
// Each participant resolves with their secret key
// For a policy (and (or A B) (or C D)), if A and C are signing:
let resolved_policy = policy
    .resolve(test_keys["A"].0).unwrap()  // A resolves their OR gate
    .resolve(test_keys["C"].0).unwrap(); // C resolves their OR gate
```

### Step 4: Create Signers

Each participant creates a `Signer` instance:

```rust
use art_of_signature::signer::Signer;

let message = b"Hello, BLISK!";

// Create signer for participant A
let mut signer_a = Signer::new(
    "Alice".into(),                    // Label for debugging
    test_keys["A"].0,                  // A's secret key
    &mut resolved_policy,              // The resolved policy tree
    message.to_vec(),                  // Message to sign
    DefaultMuSig2Hash::new(),          // Hash function
).unwrap();

// Create signer for participant C
let mut signer_c = Signer::new(
    "Charlie".into(),
    test_keys["C"].0,
    &mut resolved_policy,
    message.to_vec(),
    DefaultMuSig2Hash::new(),
).unwrap();
```

### Step 5: Run the Signature Protocol

The MuSig2 protocol runs in two rounds:

#### Round 1: Nonce Generation and Exchange

```rust
use rand::thread_rng;

// Each signer generates nonces
let a_nonces = signer_a.generate_nonces(&mut thread_rng()).unwrap();
let c_nonces = signer_c.generate_nonces(&mut thread_rng()).unwrap();

// Exchange nonces between signers
for (key, nonces) in &a_nonces {
    signer_c.process_nonces(*key, *nonces).unwrap();
}
for (key, nonces) in &c_nonces {
    signer_a.process_nonces(*key, *nonces).unwrap();
}

// Aggregate nonces (both signers should get the same result)
let aggregated_nonce = signer_a.aggregate_nonces().unwrap();
let _ = signer_c.aggregate_nonces().unwrap(); // Should match
```

#### Round 2: Partial Signature Generation and Aggregation

```rust
use art_of_signature::musig2::aggregate_partial_signatures;

// Each signer computes their partial signatures
let a_partial_sigs = signer_a.sign().unwrap();
let c_partial_sigs = signer_c.sign().unwrap();

// Combine all partial signatures
let combined_signature = aggregate_partial_signatures(
    &[a_partial_sigs, c_partial_sigs].concat(),
    aggregated_nonce,
).unwrap();
```

### Step 6: Verify the Signature

```rust
use art_of_signature::musig2::verify_signature;

// Get the aggregated public key from the policy tree root
let aggregated_public_key = resolved_policy.get_public_key().unwrap();

// Verify the signature
let is_valid = verify_signature(
    aggregated_public_key,
    message,
    &combined_signature,
    &DefaultMuSig2Hash::new(),
).unwrap();

assert!(is_valid, "Signature verification failed!");
println!("Signature verified successfully!");
```

## Complete Example

Here's a complete working example for a 2-of-2 policy with parties A and C from an `(and (or A B) (or C D))` policy:

```rust
use art_of_signature::compiler::{Compiler, CompilationOptions};
use art_of_signature::musig2::{self, DefaultMuSig2Hash, aggregate_partial_signatures, verify_signature};
use art_of_signature::parser::parse;
use art_of_signature::signer::Signer;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::{Affine as G1Affine, Fr};
use rand::thread_rng;

fn main() {
    // 1. Define the policy
    let policy_str = "(policy example (and (or A B) (or C D)))";
    
    // 2. Parse and generate keys
    let (_, expr) = parse(policy_str).unwrap();
    let test_keys = expr.generate_random_keys::<G1Affine>().unwrap();
    let public_keys = test_keys.iter().map(|(k, (_, pk))| (k.clone(), *pk)).collect();
    
    // 3. Compile the policy
    let compiler = Compiler::new();
    let options = CompilationOptions {
        public_keys,
        transform_to_cnf: true,
        aggregate: |points| musig2::aggregate_public_keys(&points, &DefaultMuSig2Hash::new()).unwrap(),
        iota: |P: G1Affine| Fr::from_le_bytes_mod_order(&P.x().unwrap().into_bigint().to_bytes_le()),
    };
    let policy = compiler.compile(&expr, options).unwrap();
    
    // 4. Resolve with signing parties (A and C)
    let mut resolved_policy = policy
        .resolve(test_keys["A"].0).unwrap()
        .resolve(test_keys["C"].0).unwrap();
    
    let message = b"Sign this message";
    
    // 5. Create signers
    let mut signer_a = Signer::new(
        "Alice".into(), test_keys["A"].0, &mut resolved_policy,
        message.to_vec(), DefaultMuSig2Hash::new(),
    ).unwrap();
    
    let mut signer_c = Signer::new(
        "Charlie".into(), test_keys["C"].0, &mut resolved_policy,
        message.to_vec(), DefaultMuSig2Hash::new(),
    ).unwrap();
    
    // 6. Round 1: Exchange nonces
    let a_nonces = signer_a.generate_nonces(&mut thread_rng()).unwrap();
    let c_nonces = signer_c.generate_nonces(&mut thread_rng()).unwrap();
    
    for (key, nonces) in &a_nonces { signer_c.process_nonces(*key, *nonces).unwrap(); }
    for (key, nonces) in &c_nonces { signer_a.process_nonces(*key, *nonces).unwrap(); }
    
    let R = signer_a.aggregate_nonces().unwrap();
    signer_c.aggregate_nonces().unwrap();
    
    // 7. Round 2: Sign and aggregate
    let sig_a = signer_a.sign().unwrap();
    let sig_c = signer_c.sign().unwrap();
    let signature = aggregate_partial_signatures(&[sig_a, sig_c].concat(), R).unwrap();
    
    // 8. Verify
    let pk = resolved_policy.get_public_key().unwrap();
    let valid = verify_signature(pk, message, &signature, &DefaultMuSig2Hash::new()).unwrap();
    
    println!("Signature valid: {}", valid);
}
```

## Policy Tree Structure

Each node in the policy tree can be:
- **Leaf node (`UserKey`)**: Contains a participant's label and public key
- **AND gate (`AndGate`)**: All children must be satisfied; resolved via MuSig2 key aggregation
- **OR gate (`OrGate`)**: At least one child must be satisfied; resolved via Diffie-Hellman key exchange

The policy is automatically converted to CNF (Conjunctive Normal Form) for efficient processing:
- Top-level AND of clauses
- Each clause is an OR of literals

For example, `(or A (and B C))` becomes `(and (or A B) (or A C))`.

### Threshold to CNF Conversion

Threshold expressions are converted to CNF using the following theorem:

> **Theorem (CNF of Threshold Functions):** For a k-of-n threshold function over variables {x₁, x₂, ..., xₙ}, 
> the CNF representation is the conjunction of all disjunctions of size m = n - k + 1.

For example, a **3-of-4 threshold** `{A, B, C, D}`:
- **DNF (disjunctive form):** `(A∧B∧C) ∨ (A∧B∧D) ∨ (A∧C∧D) ∨ (B∧C∧D)` — 4 clauses of size 3
- **CNF (conjunctive form):** `(A∨B) ∧ (A∨C) ∧ (A∨D) ∧ (B∨C) ∧ (B∨D) ∧ (C∨D)` — 6 clauses of size 2

The number of CNF clauses is C(n, n-k+1) = C(n, k-1), which is often much smaller than the DNF expansion C(n, k).

| Threshold | DNF Clauses C(n,k) | CNF Clauses C(n,m) | CNF Clause Size (m=n-k+1) |
|-----------|--------------------|--------------------|---------------------------|
| 2-of-3    | 3                  | 3                  | 2                         |
| 3-of-4    | 4                  | 6                  | 2                         |
| 2-of-4    | 6                  | 4                  | 3                         |
| 11-of-15  | 1365               | 3003               | 5                         |
| 13-of-15  | 105                | 455                | 3                         |

## API Reference

### Parser

```rust
// Parse a policy string into an expression AST
pub fn parse(input: &str) -> IResult<&str, PolicyExpr>
```

### Compiler

```rust
// Create a new compiler
pub fn new() -> Compiler

// Compile a policy expression into a policy tree
pub fn compile<G: AffineRepr>(
    &self,
    ast: &PolicyExpr,
    options: CompilationOptions<G>,
) -> Result<PolicyTree<G>, PolicyError>
```

### PolicyTree

```rust
// Resolve the tree with a participant's secret key
pub fn resolve(self, key: G::ScalarField) -> Result<Self, PolicyError>

// Get the aggregated public key (root node's key)
pub fn get_public_key(&self) -> Option<G>

// Get list of participant labels needed to resolve the policy
pub fn get_resolution_list(&self) -> Vec<String>

// Check if the policy tree is fully resolved
pub fn is_resolved(&self) -> bool
```

### Signer

```rust
// Create a new signer for a resolved policy
pub fn new(
    label: String,
    secret_key: G::ScalarField,
    policy: &mut PolicyTree<G>,
    message: Vec<u8>,
    hash_function: H,
) -> Result<Self, PolicyError>

// Generate nonces for round 1
pub fn generate_nonces(&mut self, rng: &mut impl RngCore) -> Result<Vec<(G, (G, G))>, PolicyError>

// Process nonces from other signers
pub fn process_nonces(&mut self, signer_public_key: G, nonces: (G, G)) -> Result<(), PolicyError>

// Aggregate all nonces
pub fn aggregate_nonces(&mut self) -> Result<G, PolicyError>

// Generate partial signatures
pub fn sign(&mut self) -> Result<Vec<G::ScalarField>, PolicyError>
```

### MuSig2 Utilities

```rust
// Aggregate partial signatures into final signature
pub fn aggregate_partial_signatures<G: AffineRepr>(
    partial_sigs: &[G::ScalarField],
    aggregated_nonce: G,
) -> Result<MuSig2Signature<G>, MuSig2Error>

// Verify a signature against a public key
pub fn verify_signature<G: AffineRepr, H: MuSig2HashFunction<G::ScalarField>>(
    public_key: G,
    message: &[u8],
    signature: &MuSig2Signature<G>,
    hash_function: &H,
) -> Result<bool, MuSig2Error>
```

## License

See [LICENSE](LICENSE) file.
