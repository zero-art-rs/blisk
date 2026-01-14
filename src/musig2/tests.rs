#[cfg(test)]
mod tests {
    use crate::musig2::{
        DefaultMuSig2Hash, MuSig2Session, MuSig2SessionState, aggregate_public_keys,
        aggregate_public_keys_with_coeffs, verify_signature,
    };
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::{EdwardsAffine, Fr};
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;
    use rand::{rngs::OsRng, thread_rng};

    #[test]
    fn test_musig2_full_signing_flow() {
        // Create signers with random keys
        let sk1 = Fr::rand(&mut OsRng);
        let pk1 = (EdwardsAffine::generator() * sk1).into_affine();

        let sk2 = Fr::rand(&mut OsRng);
        let pk2 = (EdwardsAffine::generator() * sk2).into_affine();

        let sk3 = Fr::rand(&mut OsRng);
        let pk3 = (EdwardsAffine::generator() * sk3).into_affine();

        // Collect all public keys
        let all_pks = vec![pk1, pk2, pk3];
        let message = b"This is a test message for MuSig2 signing".to_vec();
        let session_id = "test-session-1".to_string();

        // Create hash function
        let hash_fn = DefaultMuSig2Hash::new();

        let (agg_key, coeffs) = aggregate_public_keys_with_coeffs(&all_pks, &hash_fn).unwrap();

        // Create sessions for all signers
        let mut session1 = MuSig2Session::new(
            session_id.clone(),
            message.clone(),
            pk1,
            all_pks.clone(),
            hash_fn.clone(),
            agg_key,
            coeffs.clone(),
        )
        .expect("Session 1 creation should succeed");

        let mut session2 = MuSig2Session::new(
            session_id.clone(),
            message.clone(),
            pk2,
            all_pks.clone(),
            hash_fn.clone(),
            agg_key,
            coeffs.clone(),
        )
        .expect("Session 2 creation should succeed");

        let mut session3 = MuSig2Session::new(
            session_id.clone(),
            message.clone(),
            pk3,
            all_pks.clone(),
            hash_fn.clone(),
            agg_key,
            coeffs.clone(),
        )
        .expect("Session 3 creation should succeed");

        let agg_key = aggregate_public_keys(&all_pks, &hash_fn).unwrap();
        // Compute aggregated keys
        let _ = session1
            .compute_aggregated_key()
            .expect("Key aggregation for session 1 should succeed");
        let _ = session2
            .compute_aggregated_key()
            .expect("Key aggregation for session 2 should succeed");
        let _ = session3
            .compute_aggregated_key()
            .expect("Key aggregation for session 3 should succeed");

        // Round 1: Generate nonces
        let (r1_1, r1_2) = session1
            .generate_nonces(&mut OsRng)
            .expect("Nonce generation for session 1 should succeed");
        let (r2_1, r2_2) = session2
            .generate_nonces(&mut OsRng)
            .expect("Nonce generation for session 2 should succeed");
        let (r3_1, r3_2) = session3
            .generate_nonces(&mut OsRng)
            .expect("Nonce generation for session 3 should succeed");

        // Exchange nonces
        session1
            .add_public_nonces(pk2, (r2_1, r2_2))
            .expect("Adding nonces from signer 2 to session 1 should succeed");
        session1
            .add_public_nonces(pk3, (r3_1, r3_2))
            .expect("Adding nonces from signer 3 to session 1 should succeed");

        session2
            .add_public_nonces(pk1, (r1_1, r1_2))
            .expect("Adding nonces from signer 1 to session 2 should succeed");
        session2
            .add_public_nonces(pk3, (r3_1, r3_2))
            .expect("Adding nonces from signer 3 to session 2 should succeed");

        session3
            .add_public_nonces(pk1, (r1_1, r1_2))
            .expect("Adding nonces from signer 1 to session 3 should succeed");
        session3
            .add_public_nonces(pk2, (r2_1, r2_2))
            .expect("Adding nonces from signer 2 to session 3 should succeed");

        // Compute aggregated nonces
        let r_agg1 = session1
            .compute_aggregated_nonce()
            .expect("Nonce aggregation for session 1 should succeed");
        let r_agg2 = session2
            .compute_aggregated_nonce()
            .expect("Nonce aggregation for session 2 should succeed");
        let r_agg3 = session3
            .compute_aggregated_nonce()
            .expect("Nonce aggregation for session 3 should succeed");

        // All signers should compute the same aggregated nonce
        assert_eq!(r_agg1, r_agg2);
        assert_eq!(r_agg2, r_agg3);

        // Create partial signatures
        let _s1 = session1
            .sign(sk1)
            .expect("Signing for session 1 should succeed");
        let s2 = session2
            .sign(sk2)
            .expect("Signing for session 2 should succeed");
        let s3 = session3
            .sign(sk3)
            .expect("Signing for session 3 should succeed");

        // Exchange partial signatures
        session1
            .add_partial_signature(pk2, s2)
            .expect("Adding partial signature from signer 2 to session 1 should succeed");
        session1
            .add_partial_signature(pk3, s3)
            .expect("Adding partial signature from signer 3 to session 1 should succeed");

        // Add signatures to other sessions too for consistency
        session2
            .add_partial_signature(pk1, _s1)
            .expect("Adding partial signature from signer 1 to session 2 should succeed");
        session2
            .add_partial_signature(pk3, s3)
            .expect("Adding partial signature from signer 3 to session 2 should succeed");

        session3
            .add_partial_signature(pk1, _s1)
            .expect("Adding partial signature from signer 1 to session 3 should succeed");
        session3
            .add_partial_signature(pk2, s2)
            .expect("Adding partial signature from signer 2 to session 3 should succeed");

        // Aggregate signatures in session 1
        let signature = session1
            .aggregate_signatures()
            .expect("Signature aggregation should succeed");

        // Verify the final signature
        let result = verify_signature(agg_key, &message, &signature, &hash_fn)
            .expect("Verification should complete without errors");

        assert!(result, "Signature verification should succeed");
    }

    #[test]
    fn test_musig2_different_message() {
        // Create signers with random keys
        let sk1 = Fr::rand(&mut OsRng);
        let pk1 = (EdwardsAffine::generator() * sk1).into_affine();

        let sk2 = Fr::rand(&mut OsRng);
        let pk2 = (EdwardsAffine::generator() * sk2).into_affine();

        // Collect all public keys
        let all_pks = vec![pk1, pk2];
        let message = b"This is a test message for MuSig2 signing".to_vec();
        let wrong_message = b"This is a different message".to_vec();
        let session_id = "test-session-1".to_string();

        // Create hash function
        let hash_fn = DefaultMuSig2Hash::new();

        let (agg_key, coeffs) = aggregate_public_keys_with_coeffs(&all_pks, &hash_fn).unwrap();
        // Create sessions for all signers
        let mut session1 = MuSig2Session::new(
            session_id.clone(),
            message.clone(),
            pk1,
            all_pks.clone(),
            hash_fn.clone(),
            agg_key,
            coeffs.clone(),
        )
        .expect("Session 1 creation should succeed");

        let mut session2 = MuSig2Session::new(
            session_id.clone(),
            message.clone(),
            pk2,
            all_pks.clone(),
            hash_fn.clone(),
            agg_key,
            coeffs.clone(),
        )
        .expect("Session 2 creation should succeed");

        // Compute aggregated keys
        let (agg_key, _) = session1
            .compute_aggregated_key()
            .expect("Key aggregation for session 1 should succeed");
        let _ = session2
            .compute_aggregated_key()
            .expect("Key aggregation for session 2 should succeed");

        // Round 1: Generate nonces
        let (r1_1, r1_2) = session1
            .generate_nonces(&mut thread_rng())
            .expect("Nonce generation for session 1 should succeed");
        let (r2_1, r2_2) = session2
            .generate_nonces(&mut thread_rng())
            .expect("Nonce generation for session 2 should succeed");

        // Exchange nonces
        session1
            .add_public_nonces(pk2, (r2_1, r2_2))
            .expect("Adding nonces from signer 2 to session 1 should succeed");
        session2
            .add_public_nonces(pk1, (r1_1, r1_2))
            .expect("Adding nonces from signer 1 to session 2 should succeed");

        // Compute aggregated nonces
        let _ = session1
            .compute_aggregated_nonce()
            .expect("Nonce aggregation for session 1 should succeed");
        let _ = session2
            .compute_aggregated_nonce()
            .expect("Nonce aggregation for session 2 should succeed");

        // Create partial signatures
        let _s1 = session1
            .sign(sk1)
            .expect("Signing for session 1 should succeed");
        let s2 = session2
            .sign(sk2)
            .expect("Signing for session 2 should succeed");

        // Exchange partial signatures
        session1
            .add_partial_signature(pk2, s2)
            .expect("Adding partial signature from signer 2 to session 1 should succeed");

        // Also add the signature to the other session
        session2
            .add_partial_signature(pk1, _s1)
            .expect("Adding partial signature from signer 1 to session 2 should succeed");

        // Aggregate signatures in session 1
        let signature = session1
            .aggregate_signatures()
            .expect("Signature aggregation should succeed");

        // Verify with the correct message should succeed
        let result = verify_signature(agg_key, &message, &signature, &hash_fn)
            .expect("Verification with correct message should complete without errors");

        assert!(
            result,
            "Signature verification with correct message should succeed"
        );

        // Verify with a wrong message should fail
        let wrong_result = verify_signature(agg_key, &wrong_message, &signature, &hash_fn)
            .expect("Verification with wrong message should complete without errors");

        assert!(
            !wrong_result,
            "Signature verification with wrong message should fail"
        );
    }
}
