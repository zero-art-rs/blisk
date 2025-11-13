use ark_ec::CurveGroup;
use ark_ed25519::{EdwardsAffine, Fr};
use ark_ff::UniformRand;
use art_of_signature::{
    musig2::{
        DefaultMuSig2Hash, MuSig2, MuSig2Session, MuSig2SessionState, MuSig2Signature,
        default_musig2,
    },
    signer::Signer,
};
use rand::rngs::OsRng;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("MuSig2 Multi-Signature Example");
    println!("==============================\n");

    // Create three signers with random keys
    let sk1 = Fr::rand(&mut OsRng);
    let sk2 = Fr::rand(&mut OsRng);
    let sk3 = Fr::rand(&mut OsRng);

    let signer1 = Signer::<EdwardsAffine>::new(sk1);
    let signer2 = Signer::<EdwardsAffine>::new(sk2);
    let signer3 = Signer::<EdwardsAffine>::new(sk3);

    println!("✓ Created 3 signers with their key pairs");

    // Get public keys
    let pk1 = signer1.get_public_key();
    let pk2 = signer2.get_public_key();
    let pk3 = signer3.get_public_key();

    // Message to sign
    let message = b"This is a joint statement by three parties".to_vec();
    println!(
        "✓ Message to sign: \"{}\"",
        String::from_utf8_lossy(&message)
    );

    // Create MuSig2 protocol instance
    let musig2 = default_musig2::<EdwardsAffine>();
    let session_id = "joint-statement-1".to_string();

    // Collect all public keys
    let all_pks = vec![pk1, pk2, pk3];

    println!("\nRound 1: Session Setup");
    println!("---------------------");

    // Create sessions for all signers
    let mut session1 =
        signer1.create_musig2_session(session_id.clone(), message.clone(), all_pks.clone())?;
    let mut session2 =
        signer2.create_musig2_session(session_id.clone(), message.clone(), all_pks.clone())?;
    let mut session3 =
        signer3.create_musig2_session(session_id.clone(), message.clone(), all_pks.clone())?;

    println!("✓ Created sessions for all signers");
    println!("✓ Computed aggregated public key");

    // Print aggregated public key
    let agg_key = session1.aggregated_public_key.unwrap();
    println!("✓ Aggregated public key: {:?}", agg_key);

    println!("\nRound 2: Nonce Generation");
    println!("------------------------");

    // Generate nonces
    let (r1_1, r1_2) = signer1.generate_musig2_nonces(&mut session1)?;
    let (r2_1, r2_2) = signer2.generate_musig2_nonces(&mut session2)?;
    let (r3_1, r3_2) = signer3.generate_musig2_nonces(&mut session3)?;

    println!("✓ All signers generated their nonces");

    // Exchange nonces
    println!("✓ Exchanging nonces between signers...");
    musig2.add_public_nonces(&mut session1, pk2, (r2_1, r2_2))?;
    musig2.add_public_nonces(&mut session1, pk3, (r3_1, r3_2))?;

    musig2.add_public_nonces(&mut session2, pk1, (r1_1, r1_2))?;
    musig2.add_public_nonces(&mut session2, pk3, (r3_1, r3_2))?;

    musig2.add_public_nonces(&mut session3, pk1, (r1_1, r1_2))?;
    musig2.add_public_nonces(&mut session3, pk2, (r2_1, r2_2))?;

    println!("✓ All signers received everyone's nonces");

    // Compute aggregated nonce
    let r_agg1 = musig2.compute_aggregated_nonce(&mut session1)?;
    let r_agg2 = musig2.compute_aggregated_nonce(&mut session2)?;
    let r_agg3 = musig2.compute_aggregated_nonce(&mut session3)?;

    // All signers should compute the same aggregated nonce
    assert_eq!(r_agg1, r_agg2);
    assert_eq!(r_agg2, r_agg3);

    println!("✓ All signers computed the same aggregated nonce");
    println!("✓ Aggregated nonce: {:?}", r_agg1);

    println!("\nRound 3: Partial Signing");
    println!("-----------------------");

    // Create partial signatures
    let s1 = signer1.create_musig2_partial_signature(&mut session1)?;
    let s2 = signer2.create_musig2_partial_signature(&mut session2)?;
    let s3 = signer3.create_musig2_partial_signature(&mut session3)?;

    println!("✓ All signers created their partial signatures");

    // Exchange partial signatures
    println!("✓ Exchanging partial signatures...");
    musig2.add_partial_signature(&mut session1, pk2, s2)?;
    musig2.add_partial_signature(&mut session1, pk3, s3)?;

    println!("✓ All partial signatures collected by signer 1");

    println!("\nRound 4: Signature Aggregation");
    println!("-----------------------------");

    // Aggregate signatures
    let signature = musig2.aggregate_signatures(&mut session1)?;

    println!("✓ Final signature aggregated");
    println!("✓ Signature: ({:?}, scalar)", signature.r);

    println!("\nVerification");
    println!("-----------");

    // Verify the final signature
    let hash_fn = DefaultMuSig2Hash::new();
    let result = musig2.verify(agg_key, &message, &signature, &hash_fn)?;

    assert!(result, "Signature verification failed!");
    println!("✓ Signature verification successful!");

    // Try verifying with a wrong message
    let wrong_message = b"This is not the original message".to_vec();
    let wrong_result = musig2.verify(agg_key, &wrong_message, &signature, &hash_fn)?;

    assert!(
        !wrong_result,
        "Signature verification should fail with wrong message!"
    );
    println!("✓ Signature verification correctly fails with wrong message");

    println!("\nMuSig2 Protocol Completed Successfully!");
    Ok(())
}
