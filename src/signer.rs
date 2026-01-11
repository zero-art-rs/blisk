use crate::errors::PolicyError;
use crate::musig2::{MuSig2Error, MuSig2HashFunction, MuSig2Session, MuSig2Signature};
use crate::policy::PolicyTree;
use ark_ec::{AffineRepr, CurveGroup};
use itertools::Itertools;
use rand::RngCore;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Policy Signer
#[derive(Debug)]
pub struct Signer<G: AffineRepr, H: MuSig2HashFunction<G::ScalarField>> {
    secret_key: G::ScalarField,
    pub public_key: G,
    clauses_keys: Vec<(G::ScalarField, G)>, // resolvable keys by this signer
    musig2_sessions: Vec<MuSig2Session<G, H>>,
}

impl<G: AffineRepr, H: MuSig2HashFunction<G::ScalarField> + Clone> Signer<G, H> {
    pub fn new(
        label: String,
        secret_key: G::ScalarField,
        policy: &mut PolicyTree<G>,
        message: Vec<u8>,
        hash_function: H,
    ) -> Result<Self, PolicyError> {
        let clauses_keys = policy.resolve_clauses_private_keys(secret_key)?;
        let co_signers = policy.get_clauses_public_keys()?;
        Ok(Self {
            secret_key,
            public_key: (G::generator() * secret_key).into_affine(),
            clauses_keys: clauses_keys.clone(),
            musig2_sessions: clauses_keys
                .into_iter()
                .map(|(_, public_key)| {
                    MuSig2Session::new(
                        {
                            let pk_debug = format!("{:?}", public_key);
                            let mut hasher = DefaultHasher::new();
                            pk_debug.hash(&mut hasher);
                            format!(
                                "{}/{:08x}",
                                label.clone(),
                                (hasher.finish() & 0xffff_ffff) as u32
                            )
                        },
                        message.clone(),
                        public_key,
                        co_signers.clone(),
                        hash_function.clone(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }

    /// perform the first round of MuSig2: nonce generation
    pub fn generate_nonces(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<Vec<(G, (G, G))>, PolicyError> {
        let nonces = self
            .musig2_sessions
            .iter_mut()
            .map(|s| {
                Ok((
                    s.cosigner_public_keys[s.local_signer_idx.unwrap()],
                    s.generate_nonces(rng)?,
                ))
            })
            .collect::<Result<Vec<(G, (G, G))>, PolicyError>>()?;
        nonces // exchange nonces between internal signers
            .iter()
            .map(|(public_key, nonce)| {
                self.musig2_sessions
                    .iter_mut()
                    .filter(|s| s.cosigner_public_keys[s.local_signer_idx.unwrap()] != *public_key)
                    .map(|s| s.add_public_nonces(*public_key, *nonce))
                    .collect::<Result<(), _>>()
            })
            .collect::<Result<(), _>>()?;
        Ok(nonces)
    }

    /// process the nonces received from other signers
    pub fn process_nonces(
        &mut self,
        signer_public_key: G,
        nonces: (G, G),
    ) -> Result<(), PolicyError> {
        self.musig2_sessions
            .iter_mut()
            .map(|s| s.add_public_nonces(signer_public_key, nonces))
            .collect::<Result<(), _>>()
            .map_err(|e| e.into())
    }

    /// perform the second round of MuSig2: nonce aggregation
    pub fn aggregate_nonces(&mut self) -> Result<G, PolicyError> {
        let mut nonces = self
            .musig2_sessions
            .iter_mut()
            .map(|s| s.compute_aggregated_nonce())
            .collect::<Result<Vec<G>, _>>()?;
        nonces.dedup();
        if nonces.len() != 1 {
            return Err(MuSig2Error::InvalidNonce.into());
        }
        Ok(nonces[0])
    }

    /// get aggregated public key
    pub fn aggregate_public_keys(&mut self) -> Result<G, PolicyError> {
        let mut public_keys = self
            .musig2_sessions
            .iter_mut()
            .map(|s| s.compute_aggregated_key())
            .collect::<Result<Vec<G>, _>>()?;
        public_keys.dedup();
        if public_keys.len() != 1 {
            return Err(MuSig2Error::InvalidPublicKey.into());
        }
        Ok(public_keys[0])
    }

    /// compute partial signatures
    pub fn sign(&mut self) -> Result<Vec<G::ScalarField>, PolicyError> {
        self.musig2_sessions
            .iter_mut()
            .map(|s| {
                s.sign(
                    self.clauses_keys
                        .iter()
                        .find(|(_, Q)| Q == &s.cosigner_public_keys[s.local_signer_idx.unwrap()]) // find clause private key
                        .unwrap()
                        .0,
                )
            })
            .collect::<Result<Vec<G::ScalarField>, _>>()
            .map_err(|e| e.into())
    }

    pub fn resolve_policy(&self, policy_tree: PolicyTree<G>) -> Result<PolicyTree<G>, PolicyError> {
        policy_tree.resolve(self.secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::CompilationOptions;
    use crate::compiler::Compiler;
    use crate::musig2;
    use crate::musig2::DefaultMuSig2Hash;
    use crate::musig2::aggregate_partial_signatures;
    use crate::musig2::verify_signature;
    use crate::parser::parse;
    use ark_ff::{BigInteger, PrimeField};
    use ark_secp256k1::{Affine as G1Affine, Fr};
    use rand::thread_rng;
    use std::time::Instant;

    #[test]
    fn test_policy_3_of_4_signature() {
        let threshold_3_of_4_circuit = "(policy threshold_3_of_4_circuit
                                            (or
                                                (and A B C)
                                                (and A B D)
                                                (and A C D)
                                                (and B C D)))";
        let compiler = Compiler::new();
        let (_, expr) = parse(threshold_3_of_4_circuit).unwrap();
        // generate random keys for each party (A,B,C,D)
        let test_keys = expr.generate_random_keys().unwrap();
        let public_keys = test_keys
            .iter()
            .map(|(k, (_, pk))| (k.clone(), *pk))
            .collect();
        // initialize the compilation options
        let options = CompilationOptions {
            public_keys,
            transform_to_cnf: true, // acquire the policy circuit to be in CNF form
            aggregate: |points| {
                musig2::aggregate_public_keys(&points, &DefaultMuSig2Hash::new()).unwrap()
            }, // initialize the aggregate function of MuSig2 protocol
            iota: |P: G1Affine| {
                Fr::from_le_bytes_mod_order(&P.x().unwrap().into_bigint().to_bytes_le())
            }, // initialize the iota function for DH
        };
        let policy = compiler.compile(&expr, options).unwrap();
        let mut resolved_policy = policy
            .resolve(test_keys["A"].0)
            .unwrap()
            .resolve(test_keys["B"].0)
            .unwrap()
            .resolve(test_keys["C"].0)
            .unwrap();

        let message = b"test_message";

        // Debug: print clause public keys
        let all_clause_pks = resolved_policy.get_clauses_public_keys().unwrap();
        println!("3-of-4 Total clause public keys: {}", all_clause_pks.len());
        for (i, pk) in all_clause_pks.iter().enumerate() {
            println!("  clause_pk[{}]: {:?}", i, pk);
        }

        // create signers
        let mut signer_A = Signer::new(
            "Alice".into(),
            test_keys["A"].0,
            &mut resolved_policy,
            message.into(),
            DefaultMuSig2Hash::new(),
        )
        .unwrap();
        println!("Signer A has {} clause keys", signer_A.clauses_keys.len());
        for (i, (_, pk)) in signer_A.clauses_keys.iter().enumerate() {
            let in_clause_pks = all_clause_pks.contains(pk);
            println!(
                "  A clause_key[{}]: {:?} (in clause_pks: {})",
                i, pk, in_clause_pks
            );
        }

        let mut signer_B = Signer::new(
            "Bob".into(),
            test_keys["B"].0,
            &mut resolved_policy,
            message.into(),
            DefaultMuSig2Hash::new(),
        )
        .unwrap();
        println!("Signer B has {} clause keys", signer_B.clauses_keys.len());
        for (i, (_, pk)) in signer_B.clauses_keys.iter().enumerate() {
            let in_clause_pks = all_clause_pks.contains(pk);
            println!(
                "  B clause_key[{}]: {:?} (in clause_pks: {})",
                i, pk, in_clause_pks
            );
        }

        let mut signer_C = Signer::new(
            "Charlie".into(),
            test_keys["C"].0,
            &mut resolved_policy,
            message.into(),
            DefaultMuSig2Hash::new(),
        )
        .unwrap();
        println!("Signer C has {} clause keys", signer_C.clauses_keys.len());
        for (i, (_, pk)) in signer_C.clauses_keys.iter().enumerate() {
            let in_clause_pks = all_clause_pks.contains(pk);
            println!(
                "  C clause_key[{}]: {:?} (in clause_pks: {})",
                i, pk, in_clause_pks
            );
        }

        // now only Alice, Bob, Charlie sign the message

        // they generate nonces
        let a_nonces = signer_A.generate_nonces(&mut thread_rng()).unwrap();
        let b_nonces = signer_B.generate_nonces(&mut thread_rng()).unwrap();
        let c_nonces = signer_C.generate_nonces(&mut thread_rng()).unwrap();

        // they process nonces
        for (key, nonces) in a_nonces {
            signer_B.process_nonces(key, nonces).unwrap();
            signer_C.process_nonces(key, nonces).unwrap();
        }
        for (key, nonces) in b_nonces {
            signer_A.process_nonces(key, nonces).unwrap();
            signer_C.process_nonces(key, nonces).unwrap();
        }
        for (key, nonces) in c_nonces {
            signer_A.process_nonces(key, nonces).unwrap();
            signer_B.process_nonces(key, nonces).unwrap();
        }

        // they aggregate nonces
        let R1 = signer_A.aggregate_nonces().unwrap();
        let R2 = signer_B.aggregate_nonces().unwrap();
        let R3 = signer_C.aggregate_nonces().unwrap();

        // assure nonces are equal
        assert!(R1 == R2 && R2 == R3);

        // they sign the message
        let a_sig = signer_A.sign().unwrap();
        let b_sig = signer_B.sign().unwrap();
        let c_sig = signer_C.sign().unwrap();

        // they combine their signatures
        let combined_sig =
            aggregate_partial_signatures(&[a_sig, b_sig, c_sig].concat(), R1).unwrap();

        // aggregated public key is obtained from the root node of the resolved policy tree
        let aggregated_public_key = resolved_policy.get_public_key().unwrap();

        // one could easily verify the signature using the aggregated public key
        let verified = verify_signature(
            aggregated_public_key,
            message,
            &combined_sig,
            &DefaultMuSig2Hash::new(),
        )
        .unwrap();
        // they print the result
        println!("Verification result: {}", verified);
    }

    fn test_policy_k_of_n_signature(k: usize, n: usize) {
        use itertools::Itertools;

        // Generate all 11-of-15 combinations as AND clauses combined with OR
        let parties = {
            let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let count = n.min(26);
            (0..count)
                .map(|i| &alphabet[i..i + 1])
                .collect::<Vec<&str>>()
        };
        let combinations: Vec<String> = parties
            .iter()
            .combinations(k)
            .map(|combo| format!("(and {})", combo.iter().join(" ")))
            .collect();

        let circuit = format!(
            "(policy threshold_{k}_of_{n}_circuit\n    (or\n        {}))",
            combinations.join("\n        ")
        );

        println!("Policy 'Threshold {}/{}'", k, n);

        let compiler = Compiler::new();
        let mut start = Instant::now();
        let (_, expr) = parse(&circuit).unwrap();
        println!("Parsing time: {:?}", start.elapsed());

        start = Instant::now();
        let test_keys = expr.generate_random_keys().unwrap();
        let public_keys = test_keys
            .iter()
            .map(|(k, (_, pk))| (k.clone(), *pk))
            .collect();

        println!("Key generation time: {:?}", start.elapsed());

        start = Instant::now();
        // initialize the compilation options
        let options = CompilationOptions {
            public_keys,
            transform_to_cnf: true, // acquire the policy circuit to be in CNF form
            aggregate: |points| {
                musig2::aggregate_public_keys(&points, &DefaultMuSig2Hash::new()).unwrap()
            }, // initialize the aggregate function of MuSig2 protocol
            iota: |P: G1Affine| {
                Fr::from_le_bytes_mod_order(&P.x().unwrap().into_bigint().to_bytes_le())
            }, // initialize the iota function for DH
        };

        let policy = compiler.compile(&expr, options).unwrap();

        println!("Compilation time: {:?}", start.elapsed());

        println!("Compiled S-Expression: {}", policy.to_expr());
        println!(
            "Policy metrics: width={}, depth={}",
            policy.get_clauses_count().unwrap(),
            policy.get_maximal_clause_depth().unwrap()
        );

        start = Instant::now();
        // Resolve with k signers (first k parties)
        let signing_parties = parties[..k].to_vec();
        let mut resolved_policy = policy;
        for party in &parties {
            resolved_policy = resolved_policy.resolve(test_keys[*party].0).unwrap();
        }

        println!("Resolution time: {:?}", start.elapsed());

        let message = b"test_message_11_of_15";

        start = Instant::now();
        // create signers for the k participating parties
        let mut signers: Vec<Signer<G1Affine, DefaultMuSig2Hash<Fr>>> = signing_parties
            .iter()
            .map(|party| {
                Signer::new(
                    format!("Signer_{}", party),
                    test_keys[*party].0,
                    &mut resolved_policy,
                    message.into(),
                    DefaultMuSig2Hash::new(),
                )
                .unwrap()
            })
            .collect();

        println!("Signers creation time: {:?}", start.elapsed());

        start = Instant::now();

        // Generate nonces for all signers
        let all_nonces: Vec<Vec<(G1Affine, (G1Affine, G1Affine))>> = signers
            .iter_mut()
            .map(|s| s.generate_nonces(&mut thread_rng()).unwrap())
            .collect();

        // Process nonces: each signer receives nonces from all other signers
        for i in 0..signers.len() {
            for j in 0..signers.len() {
                if i != j {
                    for (key, nonces) in &all_nonces[j] {
                        signers[i].process_nonces(*key, *nonces).unwrap();
                    }
                }
            }
        }

        // Aggregate nonces for all signers and verify they match
        let aggregated_nonces: Vec<G1Affine> = signers
            .iter_mut()
            .map(|s| s.aggregate_nonces().unwrap())
            .collect();

        // Verify all aggregated nonces are equal
        let first_nonce = aggregated_nonces[0];
        for nonce in &aggregated_nonces {
            assert_eq!(*nonce, first_nonce, "Aggregated nonces should be equal");
        }

        println!("Signature phase1 time: {:?}", start.elapsed());

        start = Instant::now();

        // Sign the message with all signers
        let all_signatures: Vec<Vec<Fr>> = signers.iter_mut().map(|s| s.sign().unwrap()).collect();

        // Combine all partial signatures
        let combined_sig =
            aggregate_partial_signatures(&all_signatures.concat(), first_nonce).unwrap();

        println!("Signature phase2 time: {:?}", start.elapsed());

        start = Instant::now();

        // Aggregated public key is obtained from the root node of the resolved policy tree
        let aggregated_public_key = resolved_policy.get_public_key().unwrap();

        // Verify the signature using the aggregated public key
        let verified = verify_signature(
            aggregated_public_key,
            message,
            &combined_sig,
            &DefaultMuSig2Hash::new(),
        )
        .unwrap();

        println!("Verification time: {:?}", start.elapsed());

        assert!(verified, "Signature verification should succeed");
    }

    #[test]
    fn test_threshold_signature() {
        test_policy_k_of_n_signature(13, 15);
    }
}
