use std::{collections::HashMap, vec::IntoIter};

use crate::{
    errors::PolicyError,
    parser::PolicyExpr,
    policy::{PolicyNode, PolicyTree},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand};
use std::result::Result;
use tree_ds::prelude::*;

impl PolicyExpr {
    pub fn generate_random_keys<G: AffineRepr>(
        &self,
    ) -> Result<HashMap<String, (G::ScalarField, G)>, PolicyError> {
        let mut keys = HashMap::new();

        fn traverse<G: AffineRepr>(
            expr: &PolicyExpr,
            keys: &mut HashMap<String, (G::ScalarField, G)>,
        ) -> Result<(), PolicyError> {
            match expr {
                PolicyExpr::Policy { expr, .. } => traverse(expr, keys),
                PolicyExpr::Key(label) => {
                    if !keys.contains_key(label) {
                        // Generate a random scalar field element (private key)
                        let mut rng = rand::thread_rng();
                        let private_key = G::ScalarField::rand(&mut rng);

                        // Derive the public key from the private key
                        let public_key = (G::generator() * private_key).into_affine();

                        // Store the keys
                        keys.insert(label.clone(), (private_key, public_key));
                    }
                    Ok(())
                }
                PolicyExpr::And(sub_exprs) | PolicyExpr::Or(sub_exprs) => {
                    for sub_expr in sub_exprs {
                        traverse(sub_expr, keys)?;
                    }
                    Ok(())
                }
                PolicyExpr::Not(sub_expr) => traverse(sub_expr, keys),
                PolicyExpr::Threshold { subs, .. } => {
                    for sub_expr in subs {
                        traverse(sub_expr, keys)?;
                    }
                    Ok(())
                }
                PolicyExpr::WeightedThreshold { subs, .. } => {
                    for (sub_expr, _) in subs {
                        traverse(sub_expr, keys)?;
                    }
                    Ok(())
                }
            }
        }

        traverse(self, &mut keys)?;

        Ok(keys)
    }
}

pub struct Compiler {}

pub struct CompilationOptions<G: AffineRepr> {
    pub public_keys: HashMap<String, G>, // map from labels to public keys
    pub iota: fn(G) -> G::ScalarField,   // hash function for DH
    pub aggregate: fn(Vec<G>) -> G,
    pub transform_to_cnf: bool,
}

impl Compiler {
    pub fn new() -> Self {
        Compiler {}
    }

    pub fn compile<G: AffineRepr>(
        &self,
        ast: &PolicyExpr,
        options: CompilationOptions<G>,
    ) -> Result<PolicyTree<G>, PolicyError> {
        let mut idx = 0;

        let processed_ast = if options.transform_to_cnf {
            ast.to_cnf()?
        } else {
            ast.clone()
        };

        // Helper function to recursively compile the AST
        fn compile_inner<G: AffineRepr>(
            expr: &PolicyExpr,
            public_keys: &HashMap<String, G>,
            idx: &mut u64,
        ) -> Result<Tree<u64, PolicyNode<G>>, PolicyError> {
            match expr {
                PolicyExpr::Policy { expr, .. } => compile_inner(expr, public_keys, idx),
                // Convert leaf node (key) by looking up in public_keys map
                PolicyExpr::Key(label) => {
                    let key = public_keys.get(label).ok_or_else(|| {
                        PolicyError::CompilationError(format!("Key not found: {}", label))
                    })?;
                    let mut tree = Tree::new(Some(label));
                    tree.add_node(
                        Node::new(*idx, Some(PolicyNode::UserKey((label.clone(), *key)))),
                        None,
                    )
                    .map_err(|e| PolicyError::CompilationError(e.to_string()))?;
                    *idx += 1;
                    Ok(tree)
                }
                // Convert AND node - all children must be satisfied
                PolicyExpr::And(exprs) => {
                    let mut tree = Tree::new(Some("and"));
                    let root = tree
                        .add_node(Node::new(*idx, Some(PolicyNode::AndGate(None))), None)
                        .map_err(|e| PolicyError::CompilationError(e.to_string()))?;
                    *idx += 1;
                    let children: Result<Vec<_>, PolicyError> = exprs
                        .iter()
                        .map(|e| compile_inner(e, public_keys, idx))
                        .collect();

                    // Add all children to the AND node
                    for child in children? {
                        tree.add_subtree(&root, child)
                            .map_err(|e| PolicyError::CompilationError(e.to_string()))?;
                    }
                    Ok(tree)
                }
                // Convert OR node - at least one child must be satisfied
                PolicyExpr::Or(exprs) => {
                    let mut tree = Tree::new(Some("or"));
                    let root = tree
                        .add_node(Node::new(*idx, Some(PolicyNode::OrGate(None))), None)
                        .map_err(|e| PolicyError::CompilationError(e.to_string()))?;
                    *idx += 1;
                    let children: Result<Vec<_>, PolicyError> = exprs
                        .iter()
                        .map(|e| compile_inner(e, public_keys, idx))
                        .collect();

                    // Add all children to the OR node
                    for child in children? {
                        tree.add_subtree(&root, child)
                            .map_err(|e| PolicyError::CompilationError(e.to_string()))?;
                    }
                    Ok(tree)
                }
                // These operations are not yet implemented in PolicyNode
                PolicyExpr::Not(_) => Err(PolicyError::CompilationError(
                    "NOT operation is not yet implemented".to_string(),
                )),
                PolicyExpr::Threshold { .. } => Err(PolicyError::CompilationError(
                    "Threshold operation is not yet implemented".to_string(),
                )),
                PolicyExpr::WeightedThreshold { .. } => Err(PolicyError::CompilationError(
                    "WeightedThreshold operation is not yet implemented".to_string(),
                )),
            }
        }
        let name = match ast {
            PolicyExpr::Policy { name, expr: _ } => Some(name.as_str()),
            _ => None,
        };
        compile_inner(&processed_ast, &options.public_keys, &mut idx).map(|mut tree| {
            tree.rename(name);
            PolicyTree::new(
                tree,
                processed_ast.is_cnf(),
                options.iota,
                options.aggregate,
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;
    use ark_ed25519::{EdwardsAffine as G1Affine, Fr};
    use ark_ff::BigInteger;

    fn iota(p: G1Affine) -> Fr {
        Fr::from_le_bytes_mod_order(&p.x().unwrap().into_bigint().to_bytes_le())
    }

    fn aggregate(points: Vec<G1Affine>) -> G1Affine {
        points
            .iter()
            .fold(G1Affine::zero(), |acc, p| (acc + p).into())
    }

    #[test]
    fn test_compile_single_key() {
        let compiler = Compiler::new();
        let expr = PolicyExpr::Key("key1".to_string());
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: false,
        };
        let result = compiler.compile(&expr, options).unwrap();
        println!("test_compile_single_key: {}", result);
    }

    #[test]
    fn test_compile_and_expression() {
        let compiler = Compiler::new();
        let expr = PolicyExpr::And(vec![
            PolicyExpr::Key("key1".to_string()),
            PolicyExpr::Key("key2".to_string()),
        ]);
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: false,
        };
        let result = compiler.compile(&expr, options).unwrap();
        println!("test_compile_and_expression: {}", result);
    }

    #[test]
    fn test_compile_or_expression() {
        let compiler = Compiler::new();
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::Key("key1".to_string()),
            PolicyExpr::Key("key2".to_string()),
        ]);
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: false,
        };
        let result = compiler.compile(&expr, options).unwrap();
        println!("test_compile_or_expression: {}", result);
    }

    #[test]
    fn test_compile_complex_expression() {
        let compiler = Compiler::new();
        let expr = PolicyExpr::And(vec![
            PolicyExpr::Key("key1".to_string()),
            PolicyExpr::And(vec![
                PolicyExpr::Key("key2".to_string()),
                PolicyExpr::Key("key3".to_string()),
            ]),
        ]);
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: false,
        };
        let result = compiler.compile(&expr, options).unwrap();
        println!("test_compile_complex_expression: {}", result);
    }

    #[test]
    fn test_compile_invalid_key() {
        let compiler = Compiler::new();
        let public_keys = HashMap::new();
        let expr = PolicyExpr::Key("nonexistent".to_string());

        let result = compiler.compile(
            &expr,
            CompilationOptions {
                public_keys,
                iota,
                aggregate,
                transform_to_cnf: false,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_unimplemented_not() {
        let compiler = Compiler::new();
        let expr = PolicyExpr::Not(Box::new(PolicyExpr::Key("key1".to_string())));
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let result = compiler.compile(
            &expr,
            CompilationOptions {
                public_keys,
                iota,
                aggregate,
                transform_to_cnf: false,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_to_cnf() {
        let compiler = Compiler::new();
        let (_, expr) = parser::parse("(policy test_non_cnf (or A (and B (or C D))))").unwrap();
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: true,
        };

        let result = compiler.compile(&expr, options).unwrap();
        println!("{}", result);
    }

    #[test]
    fn test_compile_threshold_expression() {
        // Test compiling a threshold expression directly
        let compiler = Compiler::new();
        let (_, expr) = parser::parse("(policy threshold_2_of_3 (threshold 2 A B C))").unwrap();
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: true,
        };

        let result = compiler.compile(&expr, options).unwrap();
        println!("Compiled threshold 2-of-3: {}", result);

        // The result should be a valid policy tree
        // For 2-of-3, CNF should have C(3,2) = 3 clauses: (A∨B), (A∨C), (B∨C)
        assert_eq!(
            result.get_clauses_count().unwrap(),
            3,
            "2-of-3 threshold should have 3 clauses in CNF"
        );
    }

    #[test]
    fn test_compile_threshold_3_of_4() {
        // Test compiling a 3-of-4 threshold expression
        let compiler = Compiler::new();
        let (_, expr) = parser::parse("(policy threshold_3_of_4 (threshold 3 A B C D))").unwrap();
        let keys = expr.generate_random_keys::<G1Affine>().unwrap();
        let public_keys = keys.into_iter().map(|(k, (_, pk))| (k, pk)).collect();

        let options = CompilationOptions {
            public_keys,
            iota,
            aggregate,
            transform_to_cnf: true,
        };

        let result = compiler.compile(&expr, options).unwrap();
        println!("Compiled threshold 3-of-4: {}", result);

        // For 3-of-4, CNF should have C(4,2) = 6 clauses
        // Each clause has m = 4 - 3 + 1 = 2 elements
        assert_eq!(
            result.get_clauses_count().unwrap(),
            6,
            "3-of-4 threshold should have 6 clauses in CNF"
        );
    }
}
