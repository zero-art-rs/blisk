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
    pub fn to_cnf(&self) -> Result<PolicyExpr, PolicyError> {
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
