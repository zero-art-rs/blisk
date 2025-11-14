use crate::errors::PolicyError;
use crate::parser::PolicyExpr;
use std::collections::HashSet;
use std::hash::{BuildHasherDefault, DefaultHasher};
use std::result::Result;
/// Converts a policy expression into Conjunctive Normal Form (CNF).
///
/// The conversion follows these steps:
/// 1. Convert to Negation Normal Form (NNF) by pushing negations inward.
///    (Currently, NOT operators are not supported and will result in an error).
/// 2. Distribute OR operations over AND operations to achieve CNF.
/// 3. Restructure all OR clauses to have at most two inputs.
///
/// Note: `Threshold` and `WeightedThreshold` expressions are not supported
/// for CNF conversion and will result in an error.

impl PolicyExpr {
    /// Checks if a policy expression is already in Conjunctive Normal Form (CNF).
    ///
    /// A policy expression is in CNF if:
    /// 1. It is a single key (literal)
    /// 2. It is an OR of keys/literals (a single clause)
    /// 3. It is an AND of clauses, where each clause is an OR of keys/literals
    pub fn is_cnf(&self) -> bool {
        match self {
            // A single key is in CNF
            PolicyExpr::Key(_) => true,

            // An OR of keys is a clause, which is in CNF
            PolicyExpr::Or(subs) => {
                // Check that all subexpressions are keys (literals)
                subs.iter().all(|sub| matches!(sub, PolicyExpr::Key(_)))
            }

            // An AND of clauses is in CNF if each clause is an OR of keys
            PolicyExpr::And(subs) => {
                if subs.is_empty() {
                    return true;
                }

                subs.iter().all(|sub| {
                    match sub {
                        // A key within an AND is a degenerate clause (OR with one element)
                        PolicyExpr::Key(_) => true,

                        // An OR within an AND must only contain keys
                        PolicyExpr::Or(or_subs) => or_subs
                            .iter()
                            .all(|or_sub| matches!(or_sub, PolicyExpr::Key(_))),

                        // Any other expression within an AND means it's not in CNF
                        _ => false,
                    }
                })
            }

            // A named policy is in CNF if its inner expression is in CNF
            PolicyExpr::Policy { expr, .. } => expr.is_cnf(),

            // NOT, Threshold, and WeightedThreshold are not in CNF
            _ => false,
        }
    }

    pub fn to_cnf(&self) -> Result<PolicyExpr, PolicyError> {
        // If the expression is already in CNF, just return it
        if self.is_cnf() {
            return Ok(self.clone());
        }

        self.to_nnf()?.distribute()?.ensure_binary_or()
    }

    /// Converts the expression to Negation Normal Form (NNF).
    /// For this implementation, it primarily checks for unsupported operations.
    fn to_nnf(&self) -> Result<PolicyExpr, PolicyError> {
        match self {
            PolicyExpr::Key(_) => Ok(self.clone()),
            PolicyExpr::And(subs) => {
                let nnf_subs = subs
                    .iter()
                    .map(|sub| sub.to_nnf())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PolicyExpr::And(nnf_subs))
            }
            PolicyExpr::Or(subs) => {
                let nnf_subs = subs
                    .iter()
                    .map(|sub| sub.to_nnf())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PolicyExpr::Or(nnf_subs))
            }
            PolicyExpr::Policy { name, expr } => {
                let nnf_inner = expr.to_nnf()?;
                Ok(PolicyExpr::Policy {
                    name: name.clone(),
                    expr: Box::new(nnf_inner),
                })
            }
            PolicyExpr::Not(_) => Err(PolicyError::CompilationError(
                "CNF conversion does not support NOT operations.".to_string(),
            )),
            PolicyExpr::Threshold { .. } => Err(PolicyError::CompilationError(
                "CNF conversion does not support Threshold operations.".to_string(),
            )),
            PolicyExpr::WeightedThreshold { .. } => Err(PolicyError::CompilationError(
                "CNF conversion does not support WeightedThreshold operations.".to_string(),
            )),
        }
    }

    /// Recursively distributes OR operations over AND operations.
    /// Assumes the input expression is in NNF.
    fn distribute(&self) -> Result<PolicyExpr, PolicyError> {
        match self {
            PolicyExpr::And(subs) => {
                let processed_subs = subs
                    .iter()
                    .map(|sub| sub.distribute())
                    .collect::<Result<Vec<_>, _>>()?;
                // Flatten AND of ANDs
                let mut flattened_subs = Vec::new();
                for sub in processed_subs {
                    if let PolicyExpr::And(inner_subs) = sub {
                        flattened_subs.extend(inner_subs);
                    } else {
                        flattened_subs.push(sub);
                    }
                }

                // Apply idempotency to remove duplicates
                let mut unique_subs = Vec::new();
                for sub in flattened_subs {
                    if !unique_subs.contains(&sub) {
                        unique_subs.push(sub);
                    }
                }

                // Sort for deterministic ordering (helps with deduplication)
                unique_subs.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

                Ok(PolicyExpr::And(unique_subs))
            }
            PolicyExpr::Or(subs) => {
                // First apply idempotency - remove duplicates in inputs
                let mut unique_inputs = Vec::new();
                for sub in subs {
                    if !unique_inputs.contains(sub) {
                        unique_inputs.push(sub.clone());
                    }
                }

                // Process the deduplicated subexpressions
                let processed_subs = unique_inputs
                    .iter()
                    .map(|sub| sub.distribute())
                    .collect::<Result<Vec<_>, _>>()?;

                // Apply idempotency again after distribution
                let mut unique_subs = Vec::new();
                for sub in processed_subs {
                    if !unique_subs.contains(&sub) {
                        unique_subs.push(sub);
                    }
                }

                // Sort for deterministic ordering
                unique_subs.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

                if unique_subs.is_empty() {
                    // This represents `false`, which is not well-supported in the tree.
                    // An empty OR is usually considered false. Let's return an empty OR
                    // and let the caller decide.
                    return Ok(PolicyExpr::Or(vec![]));
                }
                let mut it = unique_subs.into_iter();
                let first = it.next().unwrap();
                it.try_fold(first, |acc, next| Self::distribute_two(&acc, &next))
            }
            PolicyExpr::Key(_) => Ok(self.clone()),
            PolicyExpr::Policy { name, expr } => Ok(PolicyExpr::Policy {
                name: name.clone(),
                expr: Box::new(expr.distribute()?),
            }),
            _ => Err(PolicyError::CompilationError(format!(
                "Unsupported expression type for CNF distribution: {:?}",
                self
            ))),
        }
    }

    // Helper to extract all literals from an expression (flattening nested ORs)
    fn extract_literals(expr: &PolicyExpr, literals: &mut Vec<PolicyExpr>) {
        match expr {
            PolicyExpr::Key(_) => {
                if !literals.contains(expr) {
                    literals.push(expr.clone());
                }
            }
            PolicyExpr::Or(subs) => {
                for sub in subs {
                    Self::extract_literals(sub, literals);
                }
            }
            _ => {
                if !literals.contains(expr) {
                    literals.push(expr.clone());
                }
            }
        }
    }

    /// checks if clause_b is a subset of clause_a (e.g. absorbs it in terms of CNF)
    fn is_subset(clause_a: &PolicyExpr, clause_b: &PolicyExpr) -> bool {
        let mut flattened_a = Vec::new();
        let mut flattened_b = Vec::new();

        Self::extract_literals(clause_a, &mut flattened_a);
        Self::extract_literals(clause_b, &mut flattened_b);

        HashSet::<PolicyExpr, BuildHasherDefault<DefaultHasher>>::from_iter(
            flattened_b.iter().cloned(),
        )
        .is_subset(&HashSet::from_iter(flattened_a.iter().cloned()))
    }

    /// Helper for `distribute`: distributes `a OR b` where `a` and `b` are CNFs.
    fn distribute_two(a: &PolicyExpr, b: &PolicyExpr) -> Result<PolicyExpr, PolicyError> {
        match (a, b) {
            (PolicyExpr::And(subs_a), PolicyExpr::And(subs_b)) => {
                let mut clauses = Vec::new();
                for sub_a in subs_a {
                    for sub_b in subs_b {
                        // Each sub_a and sub_b is a clause (an OR of literals)
                        clauses.push(Self::distribute_two(sub_a, sub_b)?);
                    }
                }

                // Deduplicate clauses (applying idempotency)
                let mut unique_clauses = Vec::new();
                for clause in clauses {
                    if !unique_clauses.contains(&clause) {
                        unique_clauses.push(clause);
                    }
                }

                Ok(PolicyExpr::And(unique_clauses))
            }
            (PolicyExpr::And(subs_a), other_b) => {
                // Distribute each term from the AND over the other expression
                let mut all_clauses = Vec::new();
                for sub_a in subs_a {
                    let distributed = Self::distribute_two(sub_a, other_b)?;

                    // If the result is an AND, add its clauses; otherwise add the clause itself
                    if let PolicyExpr::And(inner_clauses) = &distributed {
                        all_clauses.extend(inner_clauses.clone());
                    } else {
                        all_clauses.push(distributed);
                    }
                }

                // Apply idempotency to eliminate duplicate clauses
                let mut unique_clauses = Vec::new();
                for clause in all_clauses {
                    if !unique_clauses.contains(&clause) {
                        unique_clauses.push(clause);
                    }
                }

                // Sort clauses for deterministic ordering
                unique_clauses.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

                Ok(PolicyExpr::And(unique_clauses))
            }
            (other_a, PolicyExpr::And(subs_b)) => {
                // Distribute the other expression over each term from the AND
                let mut all_clauses = Vec::new();
                for sub_b in subs_b {
                    let distributed = Self::distribute_two(other_a, sub_b)?;

                    // If the result is an AND, add its clauses; otherwise add the clause itself
                    if let PolicyExpr::And(inner_clauses) = &distributed {
                        all_clauses.extend(inner_clauses.clone());
                    } else {
                        all_clauses.push(distributed);
                    }
                }

                // Apply idempotency to eliminate duplicate clauses
                let mut unique_clauses = Vec::new();
                for clause in all_clauses {
                    if !unique_clauses.contains(&clause) {
                        unique_clauses.push(clause);
                    }
                }

                // Sort clauses for deterministic ordering
                unique_clauses.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

                Ok(PolicyExpr::And(unique_clauses))
            }
            // Base case: neither expression is an AND. They must be ORs of keys, or just keys.
            (other_a, other_b) => {
                // Collect all literals from both expressions, flattening nested ORs
                let mut all_literals = Vec::new();

                // Extract literals from both expressions
                Self::extract_literals(other_a, &mut all_literals);
                Self::extract_literals(other_b, &mut all_literals);

                // Sort literals for deterministic ordering
                all_literals.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

                Ok(PolicyExpr::Or(all_literals))
            }
        }
    }

    /// Restructures OR clauses in a CNF expression to have at most two inputs.
    fn ensure_binary_or(&self) -> Result<PolicyExpr, PolicyError> {
        match self {
            PolicyExpr::And(subs) => {
                let binary_or_subs = subs
                    .iter()
                    .map(|sub| sub.ensure_binary_or())
                    .collect::<Result<Vec<_>, _>>()?;

                // Flatten AND of ANDs (helps with CNF structure)
                let mut flattened = Vec::new();
                for sub in binary_or_subs {
                    match sub {
                        PolicyExpr::And(inner_subs) => flattened.extend(inner_subs),
                        _ => flattened.push(sub),
                    }
                }

                // Sort clauses for deterministic ordering
                flattened.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
                // Apply idempotency to AND clauses
                flattened.dedup();

                // Apply absorption rule: if clause A is a subset of clause B, remove B
                let mut minimal_clauses = Vec::new();
                for clause_a in &flattened {
                    // Check if this clause is absorbed by any already included clause
                    let mut is_absorbed = false;
                    for clause_b in &minimal_clauses {
                        if Self::is_subset(clause_a, clause_b) {
                            is_absorbed = true;
                            break;
                        }
                    }

                    if !is_absorbed {
                        // If this clause wasn't absorbed, add it and remove any clauses it absorbs
                        minimal_clauses.retain(|clause_b| !Self::is_subset(clause_b, clause_a));
                        minimal_clauses.push(clause_a.clone());
                    }
                }

                Ok(PolicyExpr::And(minimal_clauses))
            }
            PolicyExpr::Or(subs) => {
                // Apply idempotency by flattening and deduplicating all OR expressions

                // Helper function to extract all literals from OR expressions
                fn flatten_or_expr(expr: &PolicyExpr, result: &mut Vec<PolicyExpr>) {
                    match expr {
                        PolicyExpr::Or(nested) => {
                            // Recursively flatten nested ORs
                            for sub in nested {
                                flatten_or_expr(sub, result);
                            }
                        }
                        _ => {
                            // Add non-OR expressions directly if not already present
                            if !result.contains(expr) {
                                result.push(expr.clone());
                            }
                        }
                    }
                }

                // Flatten all nested OR expressions and deduplicate literals
                let mut flattened = Vec::new();
                for sub in subs {
                    flatten_or_expr(sub, &mut flattened);
                }

                // Sort for deterministic ordering
                flattened.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));

                // Handle the base cases
                if flattened.is_empty() {
                    return Ok(PolicyExpr::Or(vec![]));
                } else if flattened.len() <= 2 {
                    return Ok(PolicyExpr::Or(flattened));
                } else {
                    // For more than 2 literals, build a balanced binary OR tree
                    // (instead of right-associative) for better performance

                    fn build_balanced_or_tree(literals: &[PolicyExpr]) -> PolicyExpr {
                        if literals.len() == 1 {
                            return literals[0].clone();
                        } else if literals.len() == 2 {
                            return PolicyExpr::Or(vec![literals[0].clone(), literals[1].clone()]);
                        }

                        let mid = literals.len() / 2;
                        let left = build_balanced_or_tree(&literals[..mid]);
                        let right = build_balanced_or_tree(&literals[mid..]);

                        PolicyExpr::Or(vec![left, right])
                    }

                    Ok(build_balanced_or_tree(&flattened))
                }
            }
            PolicyExpr::Key(_) => Ok(self.clone()),
            PolicyExpr::Policy { name, expr } => Ok(PolicyExpr::Policy {
                name: name.clone(),
                expr: Box::new(expr.ensure_binary_or()?),
            }),
            _ => Err(PolicyError::CompilationError(format!(
                "Unexpected expression type in CNF structure: {:?}",
                self
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    #[test]
    fn test_to_cnf_optimization() {
        // Test that expressions already in CNF are returned unchanged

        // A single key is already CNF
        let (_, key) = parser::parse("A").unwrap();
        let key_cnf = key.clone().to_cnf().unwrap();
        assert_eq!(key, key_cnf);

        // An OR of keys is already CNF
        let (_, or_expr) = parser::parse("(or A B C)").unwrap();
        let or_cnf = or_expr.clone().to_cnf().unwrap();
        assert_eq!(or_expr, or_cnf);

        // An AND of keys is already CNF
        let (_, and_expr) = parser::parse("(and A B C)").unwrap();
        let and_cnf = and_expr.clone().to_cnf().unwrap();
        assert_eq!(and_expr, and_cnf);

        // An AND of ORs of keys is already CNF
        let (_, complex_expr) = parser::parse("(and (or A B) (or C D) E)").unwrap();
        let complex_cnf = complex_expr.clone().to_cnf().unwrap();
        assert_eq!(complex_expr, complex_cnf);
    }

    #[test]
    fn test_is_cnf() {
        // Test a single key (should be CNF)
        let (_, expr1) = parser::parse("A").unwrap();
        assert!(expr1.is_cnf());

        // Test an OR of keys (should be CNF)
        let (_, expr2) = parser::parse("(or A B C)").unwrap();
        assert!(expr2.is_cnf());

        // Test an AND of keys (should be CNF)
        let (_, expr3) = parser::parse("(and A B C)").unwrap();
        assert!(expr3.is_cnf());

        // Test an AND of ORs of keys (should be CNF)
        let (_, expr4) = parser::parse("(and (or A B) (or C D) E)").unwrap();
        assert!(expr4.is_cnf());

        // Test a named policy with CNF inside (should be CNF)
        let (_, expr5) = parser::parse("(policy myPolicy (and (or A B) C))").unwrap();
        assert!(expr5.is_cnf());

        // Test NOT (should not be CNF)
        let (_, expr6) = parser::parse("(not A)").unwrap();
        assert!(!expr6.is_cnf());

        // Test nested OR (should not be CNF)
        let (_, expr7) = parser::parse("(or A (or B C))").unwrap();
        assert!(!expr7.is_cnf());

        // Test nested AND in OR (should not be CNF)
        let (_, expr8) = parser::parse("(or A (and B C))").unwrap();
        assert!(!expr8.is_cnf());

        // Test threshold (should not be CNF)
        let (_, expr9) = parser::parse("(threshold 2 A B C)").unwrap();
        assert!(!expr9.is_cnf());
    }

    #[test]
    fn test_cnf_transform() {
        let (_, expr) = parser::parse("(or A (and B (or C D)))").unwrap();
        let cnf = expr.to_cnf().unwrap();

        assert_eq!(
            cnf,
            PolicyExpr::And(vec![
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("A".into()),
                    PolicyExpr::Key("B".into())
                ]),
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("A".into()),
                    PolicyExpr::Or(vec![
                        PolicyExpr::Key("C".into()),
                        PolicyExpr::Key("D".into())
                    ])
                ])
            ])
        );
    }

    #[test]
    fn test_cnf_transform_threshold() {
        // Test the threshold 3-of-4 formula
        let (_, expr) =
            parser::parse("(or (and A B C) (and A B D) (and A C D) (and B C D))").unwrap();

        let cnf = expr.to_cnf().unwrap();
        println!("{:#?}", cnf);
        assert_eq!(
            cnf,
            PolicyExpr::And(vec![
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("A".into()),
                    PolicyExpr::Key("B".into())
                ]),
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("A".into()),
                    PolicyExpr::Key("C".into()),
                ]),
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("A".into()),
                    PolicyExpr::Key("D".into()),
                ]),
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("B".into()),
                    PolicyExpr::Key("C".into()),
                ]),
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("B".into()),
                    PolicyExpr::Key("D".into()),
                ]),
                PolicyExpr::Or(vec![
                    PolicyExpr::Key("C".into()),
                    PolicyExpr::Key("D".into()),
                ])
            ])
        );
    }

    #[test]
    fn test_idempotency() {
        // Helper to extract unique keys from any expression
        fn get_all_keys(expr: &PolicyExpr) -> Vec<String> {
            match expr {
                PolicyExpr::Key(k) => vec![k.clone()],
                PolicyExpr::Or(subs) => {
                    let mut keys = Vec::new();
                    for sub in subs {
                        keys.extend(get_all_keys(sub));
                    }
                    keys.sort();
                    keys.dedup();
                    keys
                }
                PolicyExpr::And(subs) => {
                    let mut keys = Vec::new();
                    for sub in subs {
                        keys.extend(get_all_keys(sub));
                    }
                    keys.sort();
                    keys.dedup();
                    keys
                }
                _ => vec![],
            }
        }

        // Test that duplicate literals in OR clauses are eliminated (idempotency law)
        let (_, expr) = parser::parse("(or D D D)").unwrap();
        let cnf = expr.to_cnf().unwrap();

        // Get all keys and check for duplicates
        let keys = get_all_keys(&cnf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "D".to_string());

        // Test nested ORs with duplicates
        let (_, expr2) = parser::parse("(or B (or D D D))").unwrap();
        let cnf2 = expr2.to_cnf().unwrap();

        // Get all unique keys
        let keys2 = get_all_keys(&cnf2);

        // Should have exactly B and D, no duplicates
        assert_eq!(keys2.len(), 2);
        assert!(keys2.contains(&"B".to_string()));
        assert!(keys2.contains(&"D".to_string()));

        // Add a more complex test
        let (_, expr3) = parser::parse("(or A (or B B) (or C C C))").unwrap();
        let cnf3 = expr3.to_cnf().unwrap();

        // Should contain exactly A, B, C without duplicates
        let keys3 = get_all_keys(&cnf3);
        assert_eq!(keys3.len(), 3);
        assert!(keys3.contains(&"A".to_string()));
        assert!(keys3.contains(&"B".to_string()));
        assert!(keys3.contains(&"C".to_string()));
    }
}
