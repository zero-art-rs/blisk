use crate::Expr;

/// Examples of working with the AST
impl Expr {
    /// Check if the expression contains a specific key
    pub fn contains_key(&self, key: &str) -> bool {
        match self {
            Expr::Key(k) => k == key,
            Expr::And(exprs) | Expr::Or(exprs) => exprs.iter().any(|e| e.contains_key(key)),
            Expr::Not(expr) => expr.contains_key(key),
            Expr::Threshold { subs, .. } => subs.iter().any(|e| e.contains_key(key)),
            Expr::WeightedThreshold { subs, .. } => subs.iter().any(|(e, _)| e.contains_key(key)),
        }
    }

    /// Get all unique keys in the expression
    pub fn get_all_keys(&self) -> Vec<String> {
        let mut keys = Vec::new();
        self.collect_keys(&mut keys);
        keys.sort();
        keys.dedup();
        keys
    }

    fn collect_keys(&self, keys: &mut Vec<String>) {
        match self {
            Expr::Key(k) => keys.push(k.clone()),
            Expr::And(exprs) | Expr::Or(exprs) => {
                for expr in exprs {
                    expr.collect_keys(keys);
                }
            }
            Expr::Not(expr) => expr.collect_keys(keys),
            Expr::Threshold { subs, .. } => {
                for expr in subs {
                    expr.collect_keys(keys);
                }
            }
            Expr::WeightedThreshold { subs, .. } => {
                for (expr, _) in subs {
                    expr.collect_keys(keys);
                }
            }
        }
    }

    /// Calculate total weight of a key in weighted threshold
    pub fn get_key_weight(&self, key: &str) -> u32 {
        match self {
            Expr::Key(_) => 0,
            Expr::And(exprs) | Expr::Or(exprs) => exprs.iter().map(|e| e.get_key_weight(key)).sum(),
            Expr::Not(expr) => expr.get_key_weight(key),
            Expr::Threshold { subs, .. } => subs.iter().map(|e| e.get_key_weight(key)).sum(),
            Expr::WeightedThreshold { subs, .. } => subs
                .iter()
                .filter_map(|(e, w)| {
                    if let Expr::Key(k) = e {
                        if k == key { Some(*w) } else { None }
                    } else {
                        None
                    }
                })
                .sum(),
        }
    }

    /// Get threshold parameters if this is a threshold expression
    pub fn get_threshold_params(&self) -> Option<(u32, &Vec<Expr>)> {
        if let Expr::Threshold { k, subs } = self {
            Some((*k, subs))
        } else {
            None
        }
    }

    /// Get weighted threshold parameters if this is a weighted threshold expression
    pub fn get_weighted_threshold_params(&self) -> Option<(u32, &Vec<(Expr, u32)>)> {
        if let Expr::WeightedThreshold { k, subs } = self {
            Some((*k, subs))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_key() {
        let expr = Expr::And(vec![
            Expr::Key("A".to_string()),
            Expr::Or(vec![
                Expr::Key("B".to_string()),
                Expr::Not(Box::new(Expr::Key("C".to_string()))),
            ]),
        ]);

        assert!(expr.contains_key("A"));
        assert!(expr.contains_key("B"));
        assert!(expr.contains_key("C"));
        assert!(!expr.contains_key("D"));
    }

    #[test]
    fn test_get_all_keys() {
        let expr = Expr::WeightedThreshold {
            k: 2,
            subs: vec![
                (Expr::Key("A".to_string()), 2),
                (Expr::Key("B".to_string()), 1),
                (Expr::Key("A".to_string()), 1), // Duplicate key
            ],
        };

        let keys = expr.get_all_keys();
        assert_eq!(keys, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn test_get_key_weight() {
        let expr = Expr::WeightedThreshold {
            k: 3,
            subs: vec![
                (Expr::Key("A".to_string()), 2),
                (Expr::Key("B".to_string()), 1),
                (Expr::Key("A".to_string()), 1),
            ],
        };

        assert_eq!(expr.get_key_weight("A"), 3);
        assert_eq!(expr.get_key_weight("B"), 1);
        assert_eq!(expr.get_key_weight("C"), 0);
    }

    #[test]
    fn test_get_threshold_params() {
        let expr = Expr::Threshold {
            k: 2,
            subs: vec![
                Expr::Key("A".to_string()),
                Expr::Key("B".to_string()),
                Expr::Key("C".to_string()),
            ],
        };

        if let Some((k, subs)) = expr.get_threshold_params() {
            assert_eq!(k, 2);
            assert_eq!(subs.len(), 3);
        } else {
            panic!("Expected Some, got None");
        }
    }
}
