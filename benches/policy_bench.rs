use rand::thread_rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::time::Instant;

use art_of_signature::compiler::{CompilationOptions, Compiler};
use art_of_signature::musig2::{
    self, DefaultMuSig2Hash, aggregate_partial_signatures, verify_signature,
};
use art_of_signature::parser::{PolicyExpr, parse};
use art_of_signature::signer::Signer;

use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_secp256k1::{Affine as G1Affine, Fr};

fn extract_participants(expr: &PolicyExpr, set: &mut Vec<String>) {
    match expr {
        PolicyExpr::Key(name) => {
            if !set.contains(name) {
                set.push(name.clone());
            }
        }
        PolicyExpr::And(list) | PolicyExpr::Or(list) => {
            for item in list {
                extract_participants(item, set);
            }
        }
        PolicyExpr::Threshold { k: _, subs } => {
            for item in subs {
                extract_participants(item, set);
            }
        }
        PolicyExpr::Not(sub) => extract_participants(sub, set),
        PolicyExpr::WeightedThreshold { k: _, subs } => {
            for (sub, _) in subs {
                extract_participants(sub, set);
            }
        }
        PolicyExpr::Policy {
            name: _,
            expr: sub_expr,
        } => extract_participants(sub_expr, set),
    }
}

fn select_signers(expr: &PolicyExpr) -> Vec<String> {
    match expr {
        PolicyExpr::Key(name) => vec![name.clone()],

        PolicyExpr::And(list) => {
            let mut signers = Vec::new();
            for sub_expr in list {
                let sub_signers = select_signers(sub_expr);
                for s in sub_signers {
                    if !signers.contains(&s) {
                        signers.push(s);
                    }
                }
            }
            signers
        }

        PolicyExpr::Or(list) => {
            if let Some(first) = list.first() {
                select_signers(first)
            } else {
                vec![]
            }
        }

        PolicyExpr::Threshold { k, subs } => {
            let mut signers = Vec::new();
            let k_usize = *k as usize;
            for (i, sub_expr) in subs.iter().enumerate() {
                if i >= k_usize {
                    break;
                }
                let sub_signers = select_signers(sub_expr);
                for s in sub_signers {
                    if !signers.contains(&s) {
                        signers.push(s);
                    }
                }
            }
            signers
        }

        PolicyExpr::WeightedThreshold { k, subs } => {
            vec![]
        }

        PolicyExpr::Policy {
            name: _,
            expr: sub_expr,
        } => select_signers(sub_expr),

        PolicyExpr::Not(_) => {
            vec![]
        }
    }
}

fn main() {
    let policy_str = "(policy custom_policy_2
  (threshold 20 A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 A14 A15 A16 A17 A18 A19 A20 A21 A22 A23 A24 A25 A26 A27 A28 A29 A30))";

    let message = b"Hello World!";

    let mut start_parse = Instant::now();
    let (_, expr) = parse(policy_str).expect("Failed to parse policy");
    let mut parse_time = start_parse.elapsed();
    println!("Parsing time: {:?}", parse_time);

    let mut participant_names = Vec::new();
    extract_participants(&expr, &mut participant_names);

    let active_signers = select_signers(&expr);
    println!("All participants: {:?}", participant_names);
    println!("Selected signers: {:?}", active_signers);

    let mut rng = thread_rng();
    let mut test_keys = HashMap::new();
    for name in &participant_names {
        let sk = Fr::rand(&mut rng);
        let pk: G1Affine = (G1Affine::generator() * sk).into();
        test_keys.insert(name.clone(), (sk, pk));
    }

    let public_keys: HashMap<String, G1Affine> = test_keys
        .iter()
        .map(|(k, (_, pk))| (k.clone(), *pk))
        .collect();

    let mut file = File::create("benches/custom_bench_.txt").expect("Failed to create output file");

    writeln!(file, "Policy Benchmark Results").unwrap();
    writeln!(file, "Policy: {}", policy_str).unwrap();
    writeln!(file, "Parsing time {:?}: ", parse_time).unwrap();

    let start_compile = Instant::now();
    let options = CompilationOptions {
        public_keys: public_keys.clone(),
        transform_to_cnf: true,
        aggregate: |points| {
            musig2::aggregate_public_keys(&points, &DefaultMuSig2Hash::new()).unwrap()
        },
        iota: |p: G1Affine| {
            Fr::from_le_bytes_mod_order(&p.x().unwrap().into_bigint().to_bytes_le())
        },
    };
    let compiler = Compiler::new();
    let policy = compiler.compile(&expr, options).expect("Compile failed");
    let compile_time = start_compile.elapsed();

    println!("Policy: {}", policy_str);
    println!("Compilation time: {:?}", compile_time);

    let compiled_expr = policy.to_expr();

    writeln!(file, "Compilation time: {:?}", compile_time).unwrap();
    writeln!(file, "Compiled S-Expression: {}", compiled_expr).unwrap();
    writeln!(
        file,
        "Policy metrics: width={}, depth={}",
        policy.get_clauses_count().unwrap(),
        policy.get_maximal_clause_depth().unwrap()
    )
    .unwrap();

    println!("Compiled S-Expression: {}", compiled_expr);
    println!(
        "Policy metrics: width={}, depth={}",
        policy.get_clauses_count().unwrap(),
        policy.get_maximal_clause_depth().unwrap()
    );

    let start_resolve = Instant::now();
    let mut current_resolved = policy;

    println!("Proceeding with selected signers: {:?}", active_signers);

    for name in &participant_names {
        current_resolved = current_resolved
            .resolve(test_keys[name].0)
            .expect(&format!("Failed to resolve with key: {}", name));
    }

    let resolve_time = start_resolve.elapsed();
    println!("Resolution time: {:?}", resolve_time);

    writeln!(file, "Selected signers: {:?}", active_signers).unwrap();
    writeln!(file, "Resolution time: {:?}", resolve_time).unwrap();

    let start_sign = Instant::now();

    let start_signer_init = Instant::now();
    let mut signers: Vec<Signer<G1Affine, DefaultMuSig2Hash<Fr>>> = active_signers
        .iter()
        .map(|name: &String| {
            Signer::new(
                name.clone(),
                test_keys[name].0,
                &mut current_resolved,
                message.to_vec(),
                DefaultMuSig2Hash::new(),
            )
            .expect("Signer creation failed")
        })
        .collect();
    let signer_init_time = start_signer_init.elapsed();

    let start_nonce_gen = Instant::now();
    let mut all_nonces: Vec<Vec<(G1Affine, (G1Affine, G1Affine))>> = Vec::new();
    for s in signers.iter_mut() {
        all_nonces.push(
            s.generate_nonces(&mut thread_rng())
                .expect("Nonce generation failed"),
        );
    }
    let nonce_gen_time = start_nonce_gen.elapsed();

    let start_nonce_exchange = Instant::now();
    for i in 0..signers.len() {
        for j in 0..signers.len() {
            if i != j {
                for (signer_pk, nonces) in &all_nonces[j] {
                    signers[i]
                        .process_nonces(*signer_pk, *nonces)
                        .expect("Failed to process nonce");
                }
            }
        }
    }
    let nonce_exchange_time = start_nonce_exchange.elapsed();

    let start_nonce_agg = Instant::now();
    let mut aggregated_nonces: Vec<G1Affine> = Vec::new();
    for s in signers.iter_mut() {
        let r = s.aggregate_nonces().expect("Nonce aggregation failed");
        aggregated_nonces.push(r);
    }

    let r_val = aggregated_nonces[0];
    for r in &aggregated_nonces {
        assert_eq!(
            *r, r_val,
            "All signers must compute the same aggregated nonce"
        );
    }
    let nonce_agg_time = start_nonce_agg.elapsed();

    let start_partial_sign = Instant::now();
    let all_sigs: Vec<Vec<Fr>> = signers
        .iter_mut()
        .map(|s: &mut Signer<G1Affine, DefaultMuSig2Hash<Fr>>| {
            s.sign().expect("Partial signing failed")
        })
        .collect();

    let combined_sig =
        aggregate_partial_signatures(&all_sigs.concat(), r_val).expect("Final aggregation failed");
    let partial_sign_time = start_partial_sign.elapsed();

    let total_sign_time = start_sign.elapsed();
    println!("Full Signing Protocol: {:?}", total_sign_time);

    writeln!(file, "Signer initialization time: {:?}", signer_init_time).unwrap();
    writeln!(file, "Nonce generation time: {:?}", nonce_gen_time).unwrap();
    writeln!(file, "Nonce exchange time: {:?}", nonce_exchange_time).unwrap();
    writeln!(file, "Nonce aggregation time: {:?}", nonce_agg_time).unwrap();
    writeln!(file, "Signature phase2 time: {:?}", partial_sign_time).unwrap();
    writeln!(file, "Total signing time: {:?}", total_sign_time).unwrap();

    let start_verify = Instant::now();

    let aggregated_public_key = current_resolved
        .get_public_key()
        .expect("No aggregated key - policy may not be fully resolved");

    let verified = verify_signature(
        aggregated_public_key,
        message,
        &combined_sig,
        &DefaultMuSig2Hash::new(),
    )
    .expect("Verification failed");
    let verify_time = start_verify.elapsed();

    println!("Signature verified: {}", verified);
    assert!(verified, "Signature verification must succeed");

    writeln!(file, "Verification time: {:?}", verify_time).unwrap();
}
