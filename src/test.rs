use crate::compiler::{CompilationOptions, Compiler};
use crate::musig2::{
    self, DefaultMuSig2Hash, MuSig2Error, MuSig2Signature, aggregate_partial_signatures,
    verify_signature,
};
use crate::parser::{PolicyExpr, parse};
use crate::policy::PolicyTree;
use crate::signer::Signer;
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::{Affine as G1Affine, Affine, Fr};
use rand::thread_rng;
use std::collections::{HashMap, HashSet};

pub fn key_generation(expr: &PolicyExpr) -> (HashMap<String, Affine>, HashMap<String, Fr>) {
    let test_keys: HashMap<String, (Fr, Affine)> = expr
        .generate_random_keys()
        .expect("Failed to generate keys");
    let mut pks: HashMap<String, Affine> = HashMap::with_capacity(test_keys.len());
    let mut sks: HashMap<String, Fr> = HashMap::with_capacity(test_keys.len());

    for (k, (sk, pk)) in &test_keys {
        pks.insert(k.clone(), *pk);
        sks.insert(k.clone(), *sk);
    }

    (pks, sks)
}

pub fn compile_policy(
    expr: &PolicyExpr,
    public_keys: HashMap<String, Affine>,
) -> (&PolicyExpr, PolicyTree<Affine>) {
    let compiler: Compiler = Compiler::new();
    let options = CompilationOptions {
        public_keys,
        transform_to_cnf: true,
        aggregate: |points| {
            musig2::aggregate_public_keys(&points, &DefaultMuSig2Hash::new()).unwrap()
        },
        iota: |P: G1Affine| Fr::from_le_bytes_mod_order(&P.x.into_bigint().to_bytes_le()),
    };
    let policy_tree: PolicyTree<Affine> = compiler.compile(&expr, options).unwrap();

    (expr, policy_tree)
}

pub fn resolve_policy(
    mut policy: PolicyTree<Affine>,
    all_signers: &[&str],
    secret_keys: &HashMap<String, Fr>,
) -> PolicyTree<Affine> {
    for id in all_signers {
        let sk: &Fr = secret_keys.get(*id).expect("Signer secret key not found");
        policy = policy.resolve(*sk).expect("Policy resolution failed");
    }
    policy
}

pub fn create_signers(
    signers: &Vec<&str>,
    secret_keys: HashMap<String, Fr>,
    resolved_policy: &mut PolicyTree<Affine>,
    message: &[u8; 12],
) -> HashMap<String, Signer<Affine, DefaultMuSig2Hash<Fr>>> {
    let mut signers_map: HashMap<String, Signer<Affine, DefaultMuSig2Hash<Fr>>> = HashMap::new();
    for &signer in signers {
        let temp_signer: Signer<Affine, DefaultMuSig2Hash<Fr>> = Signer::new(
            format!("signer_{}", signer).into(),
            secret_keys[signer],
            resolved_policy,
            message.into(),
            DefaultMuSig2Hash::new(),
        )
        .unwrap();
        signers_map.insert(signer.to_string(), temp_signer);
    }
    signers_map
}

pub fn create_nonces(
    signers_map: &mut HashMap<String, Signer<Affine, DefaultMuSig2Hash<Fr>>>,
) -> HashMap<String, Vec<(Affine, (Affine, Affine))>> {
    let mut nonces_map: HashMap<String, Vec<(Affine, (Affine, Affine))>> = HashMap::new();
    for (key, signer) in signers_map {
        let a_nonces: Vec<(Affine, (Affine, Affine))> =
            signer.generate_nonces(&mut thread_rng()).unwrap();
        nonces_map.insert(key.clone(), a_nonces);
    }
    nonces_map
}

pub fn processing_nonces_procedure(
    signers_map: &mut HashMap<String, Signer<Affine, DefaultMuSig2Hash<Fr>>>,
    nonces_map: &HashMap<String, Vec<(Affine, (Affine, Affine))>>,
) -> Result<(), String> {
    for (outer_key, signer) in signers_map {
        for (inner_key, nonces) in nonces_map {
            if *outer_key == *inner_key {
                continue;
            }
            for (pk, nonces) in nonces {
                signer.process_nonces(*pk, *nonces).unwrap();
            }
        }
    }
    Ok(())
}

pub fn nonces_aggregation(
    signers_map: &mut HashMap<String, Signer<Affine, DefaultMuSig2Hash<Fr>>>,
) -> Affine {
    let unique_nonces: HashSet<Affine> = signers_map
        .values_mut()
        .map(|s| s.aggregate_nonces().unwrap())
        .collect();
    unique_nonces.into_iter().next().unwrap()
}

pub fn individual_signatures_generation(
    signers_map: &mut HashMap<String, Signer<Affine, DefaultMuSig2Hash<Fr>>>,
) -> HashMap<String, Vec<Fr>> {
    let mut sig_map: HashMap<String, Vec<Fr>> = HashMap::new();
    for (key, signer) in signers_map {
        let a_sig: Vec<Fr> = signer.sign().unwrap();
        sig_map.insert(key.clone(), a_sig);
    }
    sig_map
}

pub fn signature_aggregation(
    sig_map: HashMap<String, Vec<Fr>>,
    R: Affine,
) -> MuSig2Signature<Affine> {
    let all_sigs: Vec<Fr> = sig_map
        .values()
        .flat_map(|sig| sig.iter().cloned())
        .collect();
    aggregate_partial_signatures(&all_sigs, R).unwrap()
}

fn run_blisk_simulation(
    circuit: &str,
    all_signers: Vec<&str>,
    active_signers: Vec<&str>,
) -> Result<bool, MuSig2Error> {
    let message: &[u8; 12] = b"test_message";

    let (_, expr) = parse(circuit).unwrap();
    let (public_keys, secret_keys) = key_generation(&expr);
    assert_eq!(public_keys.len(), secret_keys.len());

    let (_, policy_tree): (&PolicyExpr, PolicyTree<Affine>) = compile_policy(&expr, public_keys);
    let mut resolved_policy = resolve_policy(policy_tree, &all_signers, &secret_keys);
    let temp_check_agg_pk: Affine = resolved_policy.get_public_key().unwrap();

    let mut signers_map =
        create_signers(&active_signers, secret_keys, &mut resolved_policy, message);
    let nonces = create_nonces(&mut signers_map);
    processing_nonces_procedure(&mut signers_map, &nonces).unwrap();
    let aggregated_nonce: Affine = nonces_aggregation(&mut signers_map);

    let partial_sigs: HashMap<String, Vec<Fr>> = individual_signatures_generation(&mut signers_map);
    let aggregated_sig: MuSig2Signature<Affine> =
        signature_aggregation(partial_sigs, aggregated_nonce);

    let aggregated_public_key: Affine = resolved_policy.get_public_key().unwrap();
    assert_eq!(
        temp_check_agg_pk.to_string(),
        aggregated_public_key.to_string()
    );

    Ok(verify_signature(
        aggregated_public_key,
        message,
        &aggregated_sig,
        &DefaultMuSig2Hash::new(),
    )?)
}

#[cfg(test)]
mod blisk_tests {
    use super::*;

    fn run_case(circuit: &str, all_signers: Vec<&str>, active_signers: Vec<&str>) {
        let verified: bool = run_blisk_simulation(circuit, all_signers, active_signers).unwrap();
        assert!(verified, "Verification failed");
    }

    #[ignore]
    #[test]
    fn threshold_1_of_3() {
        let circuit: &str = "(policy threshold_1_of_3 (threshold 1 A B C))";
        let all_signers: Vec<&str> = vec!["A", "B", "C"];
        let active_signers: Vec<&str> = vec!["B"];
        run_case(circuit, all_signers, active_signers);
    }

    #[ignore]
    #[test]
    fn threshold_3_of_3_manual() {
        let circuit: &str = "(policy threshold_3_of_3 (and A B C)";
        let all_signers: Vec<&str> = vec!["A", "B", "C"];
        let active_signers: Vec<&str> = vec!["A", "B", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[ignore]
    #[test]
    fn threshold_2_of_2_manual() {
        let circuit: &str = "(policy threshold_2_of_2 (and A B)";
        let all_signers: Vec<&str> = vec!["A", "B"];
        let active_signers: Vec<&str> = vec!["A", "B"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_2_of_3() {
        let circuit: &str = "(policy threshold_2_of_3 (threshold 2 A B C))";
        let all_signers: Vec<&str> = vec!["A", "B", "C"];
        let active_signers: Vec<&str> = vec!["A", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_2_of_4_manual_v1() {
        let circuit: &str = "(policy threshold_2_of_4_manual_v1 (and (or A B) (or C D)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_2_of_4_manual_v3() {
        let circuit = "(policy threshold_2_of_4_manual_v3 (and A (or B (or C D))))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_2_of_4_manual_v4() {
        let circuit: &str = "(policy threshold_2_of_4_manual_v4
        (or (and A B)
             (and A C)
             (and A D)
             (and B C)
             (and B D)
             (and C D)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_2_of_4() {
        let circuit: &str = "(policy threshold_2_of_4 (threshold 2 A B C D))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_3_of_4_manual_v1() {
        let circuit = "(policy threshold_3_of_4_manual_v1 (and A B (or C D)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "B", "D"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_3_of_6_manual_v2() {
        let circuit: &str = "(policy threshold_3_of_6_manual_v2 (and (or A B) (or C D) (or E F)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E", "F"];
        let active_signers: Vec<&str> = vec!["A", "C", "F"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_3_of_4_manual_v3() {
        let circuit: &str = "(policy threshold_3_of_4_manual_v3
            (or
                (and A B C)
                (and A B D)
                (and A C D)
                (and B C D)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "C", "D"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_3_of_4() {
        let circuit: &str = "(policy threshold_3_of_4 (threshold 3 A B C D))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        let active_signers: Vec<&str> = vec!["A", "B", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_2_of_5() {
        let circuit: &str = "(policy threshold_2_of_5 (threshold 2 A B C D E))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let active_signers: Vec<&str> = vec!["A", "C"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_3_of_5() {
        let circuit: &str = "(policy threshold_3_of_5 (threshold 3 A B C D E))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let active_signers: Vec<&str> = vec!["A", "C", "D"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_4_of_5() {
        let circuit: &str = "(policy threshold_4_of_5 (threshold 4 A B C D E))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let active_signers: Vec<&str> = vec!["A", "B", "D", "E"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_4_of_5_manual() {
        let circuit: &str = "(policy threshold_4_of_5_manual (and A B C (or D E)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E"];
        let active_signers: Vec<&str> = vec!["A", "B", "C", "D"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_5_of_7_manual() {
        let circuit: &str = "(policy threshold_5_of_7_manual (and A B C (or D E) (or F G)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E", "F", "G"];
        let active_signers: Vec<&str> = vec!["A", "B", "C", "D", "G"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_7_of_9_manual() {
        let circuit: &str = "(policy threshold_7_of_9_manual (and A B C D E (or F G) (or H I)))";
        let all_signers: Vec<&str> = vec!["A", "B", "C", "D", "E", "F", "G", "H", "I"];
        let active_signers: Vec<&str> = vec!["A", "B", "C", "D", "E", "G", "I"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_11_of_15_manual_v1() {
        let circuit: &str =
            "(policy multisig_11_of_15 (and A B C D E F G (or H I) (or J K) (or L M) (or N O)))";
        let all_signers: Vec<&str> = vec![
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        ];
        let active_signers: Vec<&str> = vec!["A", "B", "C", "D", "E", "F", "G", "H", "J", "L", "O"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_11_of_15_manual_v2() {
        let circuit: &str =
            "(policy multisig_11_of_15 (and (or A B) C D E F G (or H I) (or J K) L M (or N O)))";
        let all_signers: Vec<&str> = vec![
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        ];
        let active_signers: Vec<&str> = vec!["A", "C", "D", "E", "F", "G", "H", "J", "L", "M", "O"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_11_of_15_v1() {
        let circuit: &str =
            "(policy multisig_11_of_15 (threshold 11 A B C D E F G H I J K L M N O))";
        let all_signers: Vec<&str> = vec![
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        ];
        let active_signers: Vec<&str> = vec!["A", "C", "D", "G", "H", "I", "J", "K", "L", "M", "O"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_11_of_15_v2() {
        let circuit: &str =
            "(policy multisig_11_of_15 (threshold 11 A B C D E F G H I J K L M N O))";
        let all_signers: Vec<&str> = vec![
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        ];
        let active_signers: Vec<&str> = vec!["A", "C", "D", "E", "F", "G", "H", "J", "L", "M", "O"];
        run_case(circuit, all_signers, active_signers);
    }

    #[test]
    fn threshold_11_of_15_v3() {
        let circuit: &str =
            "(policy multisig_11_of_15 (threshold 11 A B C D E F G H I J K L M N O))";
        let all_signers: Vec<&str> = vec![
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
        ];
        let active_signers: Vec<&str> = vec!["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"];
        run_case(circuit, all_signers, active_signers);
    }
}
