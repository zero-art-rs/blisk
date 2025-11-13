use crate::errors::PolicyError;
use crate::parser::PolicyExpr;
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
                let mut new_subs = Vec::new();
                for sub in processed_subs {
                    if let PolicyExpr::And(inner_subs) = sub {
                        new_subs.extend(inner_subs);
                    } else {
                        new_subs.push(sub);
                    }
                }
                Ok(PolicyExpr::And(new_subs))
            }
            PolicyExpr::Or(subs) => {
                let processed_subs = subs
                    .iter()
                    .map(|sub| sub.distribute())
                    .collect::<Result<Vec<_>, _>>()?;
                if processed_subs.is_empty() {
                    // This represents `false`, which is not well-supported in the tree.
                    // An empty OR is usually considered false. Let's return an empty OR
                    // and let the caller decide.
                    return Ok(PolicyExpr::Or(vec![]));
                }
                let mut it = processed_subs.into_iter();
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
                Ok(PolicyExpr::And(clauses))
            }
            (PolicyExpr::And(subs_a), other_b) => {
                let clauses = subs_a
                    .iter()
                    .map(|sub_a| Self::distribute_two(sub_a, other_b))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PolicyExpr::And(clauses))
            }
            (other_a, PolicyExpr::And(subs_b)) => {
                let clauses = subs_b
                    .iter()
                    .map(|sub_b| Self::distribute_two(other_a, sub_b))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(PolicyExpr::And(clauses))
            }
            // Base case: neither expression is an AND. They must be ORs of keys, or just keys.
            (other_a, other_b) => {
                let mut new_subs = Vec::new();
                match other_a {
                    PolicyExpr::Or(subs_a) => new_subs.extend(subs_a.clone()),
                    _ => new_subs.push(other_a.clone()),
                };
                match other_b {
                    PolicyExpr::Or(subs_b) => new_subs.extend(subs_b.clone()),
                    _ => new_subs.push(other_b.clone()),
                }
                Ok(PolicyExpr::Or(new_subs))
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
                Ok(PolicyExpr::And(binary_or_subs))
            }
            PolicyExpr::Or(subs) => {
                if subs.len() <= 2 {
                    Ok(self.clone())
                } else {
                    let mut it = subs.iter().rev();
                    let last = it.next().unwrap().clone();
                    let second_last = it.next().unwrap().clone();
                    let mut current_or = PolicyExpr::Or(vec![second_last, last]);

                    for sub in it {
                        current_or = PolicyExpr::Or(vec![sub.clone(), current_or]);
                    }
                    Ok(current_or)
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
}
