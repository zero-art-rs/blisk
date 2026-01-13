use crate::errors::PolicyError;
use crate::parser::PolicyExpr;
use itertools::Itertools;
use std::cmp::Ordering;
use std::collections::HashSet;
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

/// Helper function for deterministic ordering of PolicyExpr
fn policy_expr_cmp(a: &PolicyExpr, b: &PolicyExpr) -> Ordering {
    match (a, b) {
        (PolicyExpr::Key(ka), PolicyExpr::Key(kb)) => ka.cmp(kb),
        (PolicyExpr::Key(_), _) => Ordering::Less,
        (_, PolicyExpr::Key(_)) => Ordering::Greater,
        (PolicyExpr::Or(sa), PolicyExpr::Or(sb)) => {
            let len_cmp = sa.len().cmp(&sb.len());
            if len_cmp != Ordering::Equal {
                return len_cmp;
            }
            for (a_sub, b_sub) in sa.iter().zip(sb.iter()) {
                let sub_cmp = policy_expr_cmp(a_sub, b_sub);
                if sub_cmp != Ordering::Equal {
                    return sub_cmp;
                }
            }
            Ordering::Equal
        }
        (PolicyExpr::Or(_), _) => Ordering::Less,
        (_, PolicyExpr::Or(_)) => Ordering::Greater,
        (PolicyExpr::And(sa), PolicyExpr::And(sb)) => {
            let len_cmp = sa.len().cmp(&sb.len());
            if len_cmp != Ordering::Equal {
                return len_cmp;
            }
            for (a_sub, b_sub) in sa.iter().zip(sb.iter()) {
                let sub_cmp = policy_expr_cmp(a_sub, b_sub);
                if sub_cmp != Ordering::Equal {
                    return sub_cmp;
                }
            }
            Ordering::Equal
        }
        (PolicyExpr::And(_), _) => Ordering::Less,
        (_, PolicyExpr::And(_)) => Ordering::Greater,
        (PolicyExpr::Policy { name: na, .. }, PolicyExpr::Policy { name: nb, .. }) => na.cmp(nb),
        (PolicyExpr::Policy { .. }, _) => Ordering::Less,
        (_, PolicyExpr::Policy { .. }) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

/// Extract all literals from an expression into a HashSet (efficient for subset checks)
fn extract_literals_set(expr: &PolicyExpr) -> HashSet<PolicyExpr> {
    let mut result = HashSet::new();
    extract_literals_into_set(expr, &mut result);
    result
}

fn extract_literals_into_set(expr: &PolicyExpr, literals: &mut HashSet<PolicyExpr>) {
    match expr {
        PolicyExpr::Key(_) => {
            literals.insert(expr.clone());
        }
        PolicyExpr::Or(subs) => {
            for sub in subs {
                extract_literals_into_set(sub, literals);
            }
        }
        _ => {
            literals.insert(expr.clone());
        }
    }
}

/// Extract literals into a Vec (for building results)
fn extract_literals_vec(expr: &PolicyExpr) -> Vec<PolicyExpr> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    extract_literals_into_vec(expr, &mut result, &mut seen);
    result
}

fn extract_literals_into_vec(
    expr: &PolicyExpr,
    literals: &mut Vec<PolicyExpr>,
    seen: &mut HashSet<PolicyExpr>,
) {
    match expr {
        PolicyExpr::Key(_) => {
            if seen.insert(expr.clone()) {
                literals.push(expr.clone());
            }
        }
        PolicyExpr::Or(subs) => {
            for sub in subs {
                extract_literals_into_vec(sub, literals, seen);
            }
        }
        _ => {
            if seen.insert(expr.clone()) {
                literals.push(expr.clone());
            }
        }
    }
}

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
            // Also supports nested/binary OR trees that only contain keys
            PolicyExpr::Or(subs) => {
                // Check that all subexpressions are keys or nested ORs of keys
                subs.iter().all(|sub| Self::is_or_of_keys(sub))
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

                        // An OR within an AND must only contain keys (or nested ORs of keys)
                        PolicyExpr::Or(_) => Self::is_or_of_keys(sub),

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

    /// Helper function to check if an expression is an OR clause containing only keys
    /// Supports nested/binary OR trees (e.g., Or([Or([A, B]), Or([C, D])]))
    fn is_or_of_keys(expr: &PolicyExpr) -> bool {
        match expr {
            PolicyExpr::Key(_) => true,
            PolicyExpr::Or(subs) => subs.iter().all(|sub| Self::is_or_of_keys(sub)),
            _ => false,
        }
    }

    pub fn to_cnf(&self) -> Result<PolicyExpr, PolicyError> {
        // If the expression is already in CNF, just return it
        if self.is_cnf() {
            return Ok(self.clone());
        }

        // Handle Threshold separately - convert directly to CNF
        if let PolicyExpr::Threshold { k, subs } = self {
            return Self::threshold_to_cnf(*k, subs);
        }

        // Handle Policy wrapper with Threshold inside
        if let PolicyExpr::Policy { name, expr } = self {
            if let PolicyExpr::Threshold { k, subs } = expr.as_ref() {
                let inner_cnf = Self::threshold_to_cnf(*k, subs)?;
                return Ok(PolicyExpr::Policy {
                    name: name.clone(),
                    expr: Box::new(inner_cnf),
                });
            }
        }

        self.to_nnf()?.distribute()?.ensure_binary_or()
    }

    /// Converts a k-of-n threshold expression directly to CNF form.
    ///
    /// Based on the theorem: For a k-of-n threshold function f (the disjunction of all
    /// conjunctions of size k), the CNF is the conjunction of all disjunctions of size m = n - k + 1.
    ///
    /// For example, a 3-of-4 threshold {A, B, C, D}:
    /// - DNF: (A∧B∧C) ∨ (A∧B∧D) ∨ (A∧C∧D) ∨ (B∧C∧D)
    /// - CNF: (A∨B) ∧ (A∨C) ∧ (A∨D) ∧ (B∨C) ∧ (B∨D) ∧ (C∨D)
    ///   where each clause has size m = 4 - 3 + 1 = 2
    fn threshold_to_cnf(k: u32, subs: &[PolicyExpr]) -> Result<PolicyExpr, PolicyError> {
        let n = subs.len();
        let k = k as usize;

        // Validate inputs
        if k == 0 {
            return Err(PolicyError::CompilationError(
                "Threshold k must be at least 1".to_string(),
            ));
        }
        if k > n {
            return Err(PolicyError::CompilationError(format!(
                "Threshold k={} cannot be greater than number of subs n={}",
                k, n
            )));
        }

        // First, recursively convert all sub-expressions to CNF
        let cnf_subs: Vec<PolicyExpr> = subs
            .iter()
            .map(|sub| sub.to_cnf())
            .collect::<Result<Vec<_>, _>>()?;

        // Check if all subs are simple keys (literals)
        let all_simple_keys = cnf_subs.iter().all(|s| matches!(s, PolicyExpr::Key(_)));

        // Special case: k == n means all must sign (AND of all subs)
        if k == n {
            let and_expr = PolicyExpr::And(cnf_subs);
            return and_expr.distribute()?.ensure_binary_or();
        }

        // Special case: k == 1 means any can sign (OR of all subs)
        if k == 1 {
            // Build the OR and then convert to CNF (handles nested structures)
            let or_expr = PolicyExpr::Or(cnf_subs);
            return or_expr.distribute()?.ensure_binary_or();
        }

        // If all subs are simple keys, we can apply the theorem directly
        if all_simple_keys {
            // General case: Apply the CNF theorem
            // m = n - k + 1 is the size of each OR clause in the CNF
            let m = n - k + 1;

            // Generate all combinations of size m from the CNF-converted subs
            // Each combination becomes an OR clause in the final CNF
            let or_clauses: Vec<PolicyExpr> = cnf_subs
                .iter()
                .combinations(m)
                .map(|combo| {
                    // Each combination of m elements becomes an OR clause
                    let literals: Vec<PolicyExpr> = combo.into_iter().cloned().collect();
                    if literals.len() == 1 {
                        literals.into_iter().next().unwrap()
                    } else {
                        PolicyExpr::Or(literals)
                    }
                })
                .collect();

            // The final CNF is an AND of all these OR clauses
            let result = if or_clauses.len() == 1 {
                or_clauses.into_iter().next().unwrap()
            } else {
                PolicyExpr::And(or_clauses)
            };

            // Apply ensure_binary_or to get proper binary tree structure
            return result.ensure_binary_or();
        }

        // For complex subs (containing AND/OR), we need to expand to DNF first,
        // then convert to CNF using standard distribution.
        // DNF of k-of-n threshold: OR of all AND combinations of size k
        let dnf_conjunctions: Vec<PolicyExpr> = cnf_subs
            .iter()
            .combinations(k)
            .map(|combo| {
                let conjuncts: Vec<PolicyExpr> = combo.into_iter().cloned().collect();
                if conjuncts.len() == 1 {
                    conjuncts.into_iter().next().unwrap()
                } else {
                    PolicyExpr::And(conjuncts)
                }
            })
            .collect();

        let dnf = if dnf_conjunctions.len() == 1 {
            dnf_conjunctions.into_iter().next().unwrap()
        } else {
            PolicyExpr::Or(dnf_conjunctions)
        };

        // Now convert DNF to CNF using standard distribution
        dnf.distribute()?.ensure_binary_or()
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
            PolicyExpr::Threshold { k, subs } => {
                // Convert threshold to CNF first, then to NNF
                Self::threshold_to_cnf(*k, subs)?.to_nnf()
            }
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

                // Flatten AND of ANDs and deduplicate using HashSet
                let mut seen = HashSet::new();
                let mut flattened_subs = Vec::new();
                for sub in processed_subs {
                    if let PolicyExpr::And(inner_subs) = sub {
                        for inner in inner_subs {
                            if seen.insert(inner.clone()) {
                                flattened_subs.push(inner);
                            }
                        }
                    } else if seen.insert(sub.clone()) {
                        flattened_subs.push(sub);
                    }
                }

                // Sort for deterministic ordering
                flattened_subs.sort_by(policy_expr_cmp);

                Ok(PolicyExpr::And(flattened_subs))
            }
            PolicyExpr::Or(subs) => {
                // Deduplicate inputs using HashSet
                let mut seen = HashSet::new();
                let mut unique_inputs = Vec::new();
                for sub in subs {
                    if seen.insert(sub.clone()) {
                        unique_inputs.push(sub.clone());
                    }
                }

                // Process the deduplicated subexpressions
                let processed_subs = unique_inputs
                    .iter()
                    .map(|sub| sub.distribute())
                    .collect::<Result<Vec<_>, _>>()?;

                // Deduplicate again after distribution
                let mut seen = HashSet::new();
                let mut unique_subs = Vec::new();
                for sub in processed_subs {
                    if seen.insert(sub.clone()) {
                        unique_subs.push(sub);
                    }
                }

                // Sort for deterministic ordering
                unique_subs.sort_by(policy_expr_cmp);

                if unique_subs.is_empty() {
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

    /// checks if clause_b is a subset of clause_a (e.g. absorbs it in terms of CNF)
    fn is_subset_with_sets(set_a: &HashSet<PolicyExpr>, set_b: &HashSet<PolicyExpr>) -> bool {
        set_b.is_subset(set_a)
    }

    /// Helper for `distribute`: distributes `a OR b` where `a` and `b` are CNFs.
    fn distribute_two(a: &PolicyExpr, b: &PolicyExpr) -> Result<PolicyExpr, PolicyError> {
        match (a, b) {
            (PolicyExpr::And(subs_a), PolicyExpr::And(subs_b)) => {
                // Use HashSet for efficient deduplication
                let mut seen = HashSet::new();
                let mut clauses = Vec::new();

                for sub_a in subs_a {
                    for sub_b in subs_b {
                        let clause = Self::distribute_two(sub_a, sub_b)?;
                        if seen.insert(clause.clone()) {
                            clauses.push(clause);
                        }
                    }
                }

                Ok(PolicyExpr::And(clauses))
            }
            (PolicyExpr::And(subs_a), other_b) => {
                let mut seen = HashSet::new();
                let mut all_clauses = Vec::new();

                for sub_a in subs_a {
                    let distributed = Self::distribute_two(sub_a, other_b)?;

                    if let PolicyExpr::And(inner_clauses) = distributed {
                        for clause in inner_clauses {
                            if seen.insert(clause.clone()) {
                                all_clauses.push(clause);
                            }
                        }
                    } else if seen.insert(distributed.clone()) {
                        all_clauses.push(distributed);
                    }
                }

                // Sort clauses for deterministic ordering
                all_clauses.sort_by(policy_expr_cmp);

                Ok(PolicyExpr::And(all_clauses))
            }
            (other_a, PolicyExpr::And(subs_b)) => {
                let mut seen = HashSet::new();
                let mut all_clauses = Vec::new();

                for sub_b in subs_b {
                    let distributed = Self::distribute_two(other_a, sub_b)?;

                    if let PolicyExpr::And(inner_clauses) = distributed {
                        for clause in inner_clauses {
                            if seen.insert(clause.clone()) {
                                all_clauses.push(clause);
                            }
                        }
                    } else if seen.insert(distributed.clone()) {
                        all_clauses.push(distributed);
                    }
                }

                // Sort clauses for deterministic ordering
                all_clauses.sort_by(policy_expr_cmp);

                Ok(PolicyExpr::And(all_clauses))
            }
            // Base case: neither expression is an AND. They must be ORs of keys, or just keys.
            (other_a, other_b) => {
                // Use efficient literal extraction with HashSet
                let mut all_literals = extract_literals_vec(other_a);
                let mut seen: HashSet<PolicyExpr> = all_literals.iter().cloned().collect();

                // Add literals from other_b
                let literals_b = extract_literals_vec(other_b);
                for lit in literals_b {
                    if seen.insert(lit.clone()) {
                        all_literals.push(lit);
                    }
                }

                // Sort literals for deterministic ordering
                all_literals.sort_by(policy_expr_cmp);

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

                // Flatten AND of ANDs using HashSet for deduplication
                let mut seen = HashSet::new();
                let mut flattened = Vec::new();
                for sub in binary_or_subs {
                    match sub {
                        PolicyExpr::And(inner_subs) => {
                            for inner in inner_subs {
                                if seen.insert(inner.clone()) {
                                    flattened.push(inner);
                                }
                            }
                        }
                        _ => {
                            if seen.insert(sub.clone()) {
                                flattened.push(sub);
                            }
                        }
                    }
                }

                // Sort clauses for deterministic ordering
                flattened.sort_by(policy_expr_cmp);

                // Apply absorption rule with pre-computed literal sets
                // First, compute all literal sets
                let literal_sets: Vec<HashSet<PolicyExpr>> = flattened
                    .iter()
                    .map(|clause| extract_literals_set(clause))
                    .collect();

                let mut minimal_indices: Vec<usize> = Vec::new();

                for (i, set_a) in literal_sets.iter().enumerate() {
                    // Check if this clause is absorbed by any already included clause
                    let mut is_absorbed = false;
                    for &j in &minimal_indices {
                        if Self::is_subset_with_sets(set_a, &literal_sets[j]) {
                            is_absorbed = true;
                            break;
                        }
                    }

                    if !is_absorbed {
                        // Remove any clauses absorbed by this one
                        minimal_indices
                            .retain(|&j| !Self::is_subset_with_sets(&literal_sets[j], set_a));
                        minimal_indices.push(i);
                    }
                }

                let minimal_clauses: Vec<PolicyExpr> = minimal_indices
                    .into_iter()
                    .map(|i| flattened[i].clone())
                    .collect();

                Ok(PolicyExpr::And(minimal_clauses))
            }
            PolicyExpr::Or(subs) => {
                // Flatten and deduplicate using HashSet
                let mut seen = HashSet::new();
                let mut flattened = Vec::new();

                fn flatten_or_expr(
                    expr: &PolicyExpr,
                    result: &mut Vec<PolicyExpr>,
                    seen: &mut HashSet<PolicyExpr>,
                ) {
                    match expr {
                        PolicyExpr::Or(nested) => {
                            for sub in nested {
                                flatten_or_expr(sub, result, seen);
                            }
                        }
                        _ => {
                            if seen.insert(expr.clone()) {
                                result.push(expr.clone());
                            }
                        }
                    }
                }

                for sub in subs {
                    flatten_or_expr(sub, &mut flattened, &mut seen);
                }

                // Sort for deterministic ordering
                flattened.sort_by(policy_expr_cmp);

                // Handle the base cases
                if flattened.is_empty() {
                    return Ok(PolicyExpr::Or(vec![]));
                } else if flattened.len() <= 2 {
                    return Ok(PolicyExpr::Or(flattened));
                } else {
                    // For more than 2 literals, build a balanced binary OR tree

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
    use crate::parser::parse;

    #[test]
    fn test_to_cnf_optimization() {
        // Create a moderately complex expression that would expose inefficiencies
        // (A OR B) AND (C OR D) should remain unchanged
        let (_, expr) = parse("(and (or A B) (or C D))").unwrap();
        let cnf = expr.to_cnf().unwrap();
        assert!(cnf.is_cnf());

        // (A AND B) OR (C AND D) should become (A OR C) AND (A OR D) AND (B OR C) AND (B OR D)
        let (_, expr2) = parse("(or (and A B) (and C D))").unwrap();
        let cnf2 = expr2.to_cnf().unwrap();
        assert!(cnf2.is_cnf());

        // Verify the structure
        if let PolicyExpr::And(clauses) = &cnf2 {
            assert_eq!(clauses.len(), 4);
        } else {
            panic!("Expected AND at top level");
        }
    }

    #[test]
    fn test_is_cnf() {
        // Single key should be CNF
        let expr = PolicyExpr::Key("A".to_string());
        assert!(expr.is_cnf());

        // AND of keys should be CNF
        let expr = PolicyExpr::And(vec![
            PolicyExpr::Key("A".to_string()),
            PolicyExpr::Key("B".to_string()),
        ]);
        assert!(expr.is_cnf());

        // OR of keys should be CNF
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::Key("A".to_string()),
            PolicyExpr::Key("B".to_string()),
        ]);
        assert!(expr.is_cnf());

        // AND of ORs of keys should be CNF
        let expr = PolicyExpr::And(vec![
            PolicyExpr::Or(vec![
                PolicyExpr::Key("A".to_string()),
                PolicyExpr::Key("B".to_string()),
            ]),
            PolicyExpr::Or(vec![
                PolicyExpr::Key("C".to_string()),
                PolicyExpr::Key("D".to_string()),
            ]),
        ]);
        assert!(expr.is_cnf());

        // OR of ANDs should NOT be CNF
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::And(vec![
                PolicyExpr::Key("A".to_string()),
                PolicyExpr::Key("B".to_string()),
            ]),
            PolicyExpr::And(vec![
                PolicyExpr::Key("C".to_string()),
                PolicyExpr::Key("D".to_string()),
            ]),
        ]);
        assert!(!expr.is_cnf());

        // Nested binary ORs of keys should be CNF
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::Or(vec![
                PolicyExpr::Key("A".to_string()),
                PolicyExpr::Key("B".to_string()),
            ]),
            PolicyExpr::Or(vec![
                PolicyExpr::Key("C".to_string()),
                PolicyExpr::Key("D".to_string()),
            ]),
        ]);
        assert!(expr.is_cnf());
    }

    #[test]
    fn test_to_cnf_result_is_cnf() {
        let test_cases = [
            "(and A B)",
            "(or A B)",
            "(or (and A B) (and C D))",
            "(and (or A B) (or C D))",
            "(or A (and B C))",
            "(and A (or B C))",
            "(or (and A B) C)",
            "(and (or A B) C)",
            "(or (and A B) (and C (or D E)))",
            "(and (or A B) (and C (or D E)))",
            // More complex cases
            "(or (and A B C) (and D E F))",
            "(or (and A (or B C)) (and D (or E F)))",
        ];

        for input in &test_cases {
            let (_, expr) = parse(input).expect(&format!("Failed to parse: {}", input));
            let cnf_result = expr.to_cnf();

            match cnf_result {
                Ok(cnf) => {
                    assert!(
                        cnf.is_cnf(),
                        "CNF result for '{}' is not in CNF form: {:?}",
                        input,
                        cnf
                    );
                }
                Err(e) => {
                    panic!("CNF conversion failed for '{}': {:?}", input, e);
                }
            }
        }
    }

    #[test]
    fn test_cnf_transform_3_of_5() {
        // Test 3-of-5 threshold as DNF (manually expanded)
        let policy_3_of_5 = "(or (and A B C) (and A B D) (and A B E) (and A C D) (and A C E) (and A D E) (and B C D) (and B C E) (and B D E) (and C D E))";
        let (_, expr) = parse(policy_3_of_5).unwrap();
        let cnf_result = expr.to_cnf();
        assert!(cnf_result.is_ok());
        let cnf = cnf_result.unwrap();
        assert!(cnf.is_cnf(), "Result should be valid CNF");
    }

    #[test]
    fn test_cnf_transform() {
        let test_cases = [
            "(and A B)",
            "(or A B)",
            "(or (and A B) (and C D))",
            "(and (or A B) (or C D))",
            "(or A (and B C))",
        ];

        for input in test_cases {
            let (_, expr) = parse(input).expect(&format!("Failed to parse: {}", input));
            let cnf_result = expr.to_cnf();
            assert!(cnf_result.is_ok(), "CNF conversion failed for: {}", input);
            let cnf = cnf_result.unwrap();
            assert!(cnf.is_cnf(), "Result is not in CNF form for: {}", input);
        }
    }

    #[test]
    fn test_cnf_transform_threshold() {
        // Test the threshold 3-of-4 formula (manually expanded as DNF)
        let (_, expr) = parse("(or (and A B C) (and A B D) (and A C D) (and B C D))").unwrap();

        let cnf = expr.to_cnf().unwrap();
        assert!(cnf.is_cnf(), "Result should be valid CNF");

        // The CNF should have 6 clauses: (A OR B), (A OR C), (A OR D), (B OR C), (B OR D), (C OR D)
        if let PolicyExpr::And(clauses) = &cnf {
            assert_eq!(clauses.len(), 6, "Expected 6 clauses for 3-of-4 threshold");
        } else {
            panic!("Expected AND at top level");
        }
    }

    #[test]
    fn test_idempotency() {
        // Helper function to extract all keys from an expression
        fn get_all_keys(expr: &PolicyExpr) -> Vec<String> {
            match expr {
                PolicyExpr::Key(k) => vec![k.clone()],
                PolicyExpr::And(subs) | PolicyExpr::Or(subs) => {
                    subs.iter().flat_map(|s| get_all_keys(s)).collect()
                }
                PolicyExpr::Policy { expr, .. } => get_all_keys(expr),
                _ => vec![],
            }
        }

        // Test cases where idempotency should reduce the expression
        let test_cases = [
            // A OR A should become just A
            "(or A A)",
            // A AND A should become just A
            "(and A A)",
            // (A OR B) AND (A OR B) should become just (A OR B)
            "(and (or A B) (or A B))",
            // More complex: (A AND B) OR (A AND B) should become A AND B
            "(or (and A B) (and A B))",
        ];

        for input in test_cases {
            let (_, expr) = parse(input).expect(&format!("Failed to parse: {}", input));
            let cnf = expr.to_cnf().expect(&format!("CNF failed for: {}", input));

            // Get keys before and after
            let original_keys: std::collections::HashSet<_> =
                get_all_keys(&expr).into_iter().collect();
            let cnf_keys: std::collections::HashSet<_> = get_all_keys(&cnf).into_iter().collect();

            // The CNF should have the same unique keys (semantically equivalent)
            assert_eq!(
                original_keys, cnf_keys,
                "Keys changed for: {} -> {:?}",
                input, cnf
            );

            // And it should be in CNF form
            assert!(cnf.is_cnf(), "Not CNF for: {} -> {:?}", input, cnf);
        }
    }

    #[test]
    fn test_threshold_to_cnf_2_of_3() {
        // 2-of-3 threshold: (threshold 2 A B C)
        // DNF equivalent: (or (and A B) (and A C) (and B C))
        // CNF should be: (A or B) and (A or C) and (B or C) -- each clause has m = 3 - 2 + 1 = 2 elements
        let (_, expr) = parse("(threshold 2 A B C)").unwrap();
        let cnf = expr.to_cnf().unwrap();

        assert!(cnf.is_cnf(), "Result should be valid CNF: {:?}", cnf);

        // Should have C(3,2) = 3 clauses
        if let PolicyExpr::And(clauses) = &cnf {
            assert_eq!(clauses.len(), 3, "Expected 3 clauses for 2-of-3 threshold");
        } else {
            panic!("Expected AND at top level, got: {:?}", cnf);
        }
    }

    #[test]
    fn test_threshold_to_cnf_3_of_4() {
        // 3-of-4 threshold: (threshold 3 A B C D)
        // CNF should have C(4,2) = 6 clauses, each with m = 4 - 3 + 1 = 2 elements
        let (_, expr) = parse("(threshold 3 A B C D)").unwrap();
        let cnf = expr.to_cnf().unwrap();

        assert!(cnf.is_cnf(), "Result should be valid CNF: {:?}", cnf);

        if let PolicyExpr::And(clauses) = &cnf {
            assert_eq!(clauses.len(), 6, "Expected 6 clauses for 3-of-4 threshold");
        } else {
            panic!("Expected AND at top level, got: {:?}", cnf);
        }
    }

    #[test]
    fn test_threshold_to_cnf_2_of_4() {
        // 2-of-4 threshold: (threshold 2 A B C D)
        // CNF should have C(4,3) = 4 clauses, each with m = 4 - 2 + 1 = 3 elements
        let (_, expr) = parse("(threshold 2 A B C D)").unwrap();
        let cnf = expr.to_cnf().unwrap();

        assert!(cnf.is_cnf(), "Result should be valid CNF: {:?}", cnf);

        if let PolicyExpr::And(clauses) = &cnf {
            assert_eq!(clauses.len(), 4, "Expected 4 clauses for 2-of-4 threshold");
        } else {
            panic!("Expected AND at top level, got: {:?}", cnf);
        }
    }

    #[test]
    fn test_threshold_to_cnf_special_cases() {
        // k = n (all must sign) -> should become AND
        let (_, expr) = parse("(threshold 3 A B C)").unwrap();
        let cnf = expr.to_cnf().unwrap();
        assert!(cnf.is_cnf(), "k=n case should be valid CNF");

        // k = 1 (any can sign) -> should become OR
        let (_, expr) = parse("(threshold 1 A B C)").unwrap();
        let cnf = expr.to_cnf().unwrap();
        assert!(cnf.is_cnf(), "k=1 case should be valid CNF");
    }

    #[test]
    fn test_threshold_to_cnf_with_policy_wrapper() {
        // Test threshold inside a policy wrapper
        let (_, expr) = parse("(policy my_threshold (threshold 2 A B C))").unwrap();
        let cnf = expr.to_cnf().unwrap();

        assert!(cnf.is_cnf(), "Result should be valid CNF: {:?}", cnf);

        // Should preserve the policy wrapper
        if let PolicyExpr::Policy { name, expr: inner } = &cnf {
            assert_eq!(name, "my_threshold");
            assert!(inner.is_cnf(), "Inner expression should be CNF");
        } else {
            panic!("Expected Policy wrapper, got: {:?}", cnf);
        }
    }

    #[test]
    fn test_threshold_equivalence_to_manual_dnf() {
        // Verify that (threshold 3 A B C D) produces same CNF as manual DNF expansion
        let (_, threshold_expr) = parse("(threshold 3 A B C D)").unwrap();
        let (_, dnf_expr) =
            parse("(or (and A B C) (and A B D) (and A C D) (and B C D))").unwrap();

        let threshold_cnf = threshold_expr.to_cnf().unwrap();
        let dnf_cnf = dnf_expr.to_cnf().unwrap();

        // Both should produce CNF with 6 clauses
        if let (PolicyExpr::And(t_clauses), PolicyExpr::And(d_clauses)) =
            (&threshold_cnf, &dnf_cnf)
        {
            assert_eq!(
                t_clauses.len(),
                d_clauses.len(),
                "Threshold and DNF should produce same number of clauses"
            );
        } else {
            panic!(
                "Both should be AND expressions: threshold={:?}, dnf={:?}",
                threshold_cnf, dnf_cnf
            );
        }
    }

    #[test]
    fn test_threshold_invalid_k() {
        // k > n should fail
        let expr = PolicyExpr::Threshold {
            k: 5,
            subs: vec![
                PolicyExpr::Key("A".to_string()),
                PolicyExpr::Key("B".to_string()),
                PolicyExpr::Key("C".to_string()),
            ],
        };
        assert!(expr.to_cnf().is_err(), "k > n should fail");

        // k = 0 should fail
        let expr = PolicyExpr::Threshold {
            k: 0,
            subs: vec![
                PolicyExpr::Key("A".to_string()),
                PolicyExpr::Key("B".to_string()),
            ],
        };
        assert!(expr.to_cnf().is_err(), "k = 0 should fail");
    }

    #[test]
    fn test_threshold_with_nested_expressions() {
        // Threshold with nested AND/OR expressions as subs
        // For (threshold 2 X Y Z) where X=(and A B), Y=(or C D), Z=E
        // This is a 2-of-3 threshold, so we need at least 2 of the 3 subs to be satisfied
        let (_, expr) = parse("(threshold 2 (and A B) (or C D) E)").unwrap();
        let cnf = expr.to_cnf().unwrap();

        assert!(cnf.is_cnf(), "Nested threshold should produce valid CNF: {:?}", cnf);

        // Also test simpler nested case
        let (_, expr2) = parse("(threshold 2 (and A B) C D)").unwrap();
        let cnf2 = expr2.to_cnf().unwrap();
        assert!(cnf2.is_cnf(), "Simpler nested threshold should produce valid CNF: {:?}", cnf2);
    }
}
