use std::collections::HashMap;

use crate::{
    errors::PolicyError,
    parser::PolicyExpr,
    policy::{PolicyNode, PolicyTree},
};
use ark_ec::AffineRepr;
use std::result::Result;
use tree_ds::prelude::*;

pub struct Compiler {}

impl Compiler {
    pub fn new() -> Self {
        Compiler {}
    }

    pub fn compile<G: AffineRepr>(
        &self,
        ast: &PolicyExpr,
        public_keys: HashMap<String, G>, // map from labels to public keys
    ) -> Result<PolicyTree<G>, PolicyError> {
        let mut idx = 0;
        // Helper function to recursively compile the AST
        fn compile_inner<G: AffineRepr>(
            expr: &PolicyExpr,
            public_keys: &HashMap<String, G>,
            idx: &mut u64,
        ) -> Result<Tree<u64, PolicyNode<G>>, PolicyError> {
            match expr {
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

        compile_inner(ast, &public_keys, &mut idx).map(PolicyTree::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Affine};
    use ark_ec::CurveGroup;
    use std::ops::Mul;

    fn setup_test_keys() -> HashMap<String, G1Affine> {
        let mut public_keys = HashMap::new();
        // Generate some test public keys using random scalars
        for i in 1..=3 {
            let scalar = Fr::from(i as u64);
            let point = G1Affine::generator().mul(scalar).into_affine();
            public_keys.insert(format!("key{}", i), point);
        }
        public_keys
    }

    #[test]
    fn test_compile_single_key() {
        let compiler = Compiler::new();
        let public_keys = setup_test_keys();
        let expr = PolicyExpr::Key("key1".to_string());

        let result = compiler.compile(&expr, public_keys.clone()).unwrap();
        println!("test_compile_single_key: {}", result);
    }

    #[test]
    fn test_compile_and_expression() {
        let compiler = Compiler::new();
        let public_keys = setup_test_keys();
        let expr = PolicyExpr::And(vec![
            PolicyExpr::Key("key1".to_string()),
            PolicyExpr::Key("key2".to_string()),
        ]);

        let result = compiler.compile(&expr, public_keys.clone()).unwrap();
        println!("test_compile_and_expression: {}", result);
    }

    #[test]
    fn test_compile_or_expression() {
        let compiler = Compiler::new();
        let public_keys = setup_test_keys();
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::Key("key1".to_string()),
            PolicyExpr::Key("key2".to_string()),
        ]);

        let result = compiler.compile(&expr, public_keys.clone()).unwrap();
        println!("test_compile_or_expression: {}", result);
    }

    #[test]
    fn test_compile_complex_expression() {
        let compiler = Compiler::new();
        let public_keys = setup_test_keys();
        let expr = PolicyExpr::And(vec![
            PolicyExpr::Key("key1".to_string()),
            PolicyExpr::Or(vec![
                PolicyExpr::Key("key2".to_string()),
                PolicyExpr::Key("key3".to_string()),
            ]),
        ]);

        let result = compiler.compile(&expr, public_keys.clone()).unwrap();
        println!("test_compile_complex_expression: {}", result);
    }

    #[test]
    fn test_compile_invalid_key() {
        let compiler = Compiler::new();
        let public_keys = setup_test_keys();
        let expr = PolicyExpr::Key("nonexistent".to_string());

        let result = compiler.compile(&expr, public_keys.clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_compile_unimplemented_not() {
        let compiler = Compiler::new();
        let public_keys = setup_test_keys();
        let expr = PolicyExpr::Not(Box::new(PolicyExpr::Key("key1".to_string())));

        let result = compiler.compile(&expr, public_keys.clone());
        assert!(result.is_err());
    }
}
