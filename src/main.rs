mod examples;

use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::{char, multispace0, space1, u32 as parse_u32},
    multi::separated_list0,
    sequence::{delimited, preceded},
};

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Key(String),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    Threshold { k: u32, subs: Vec<Expr> },
    WeightedThreshold { k: u32, subs: Vec<(Expr, u32)> },
}

/// ======= Parser =======

fn identifier(input: &str) -> IResult<&str, String> {
    take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '-')
        .map(|s: &str| s.to_string())
        .parse(input)
}

fn key_expr(input: &str) -> IResult<&str, Expr> {
    identifier.map(Expr::Key).parse(input)
}

fn expr(input: &str) -> IResult<&str, Expr> {
    preceded(multispace0, alt((list_expr, key_expr))).parse(input)
}

fn list_expr(input: &str) -> IResult<&str, Expr> {
    delimited(
        preceded(multispace0, char('(')),
        preceded(
            multispace0,
            alt((
                parse_and,
                parse_or,
                parse_not,
                parse_threshold,
                parse_weighted_threshold,
            )),
        ),
        preceded(multispace0, char(')')),
    )
    .parse(input)
}

fn parse_and(input: &str) -> IResult<&str, Expr> {
    tag("and")
        .and(space1)
        .and(separated_list0(space1, expr))
        .map(|(_, exprs)| Expr::And(exprs))
        .parse(input)
}

fn parse_or(input: &str) -> IResult<&str, Expr> {
    tag("or")
        .and(space1)
        .and(separated_list0(space1, expr))
        .map(|(_, exprs)| Expr::Or(exprs))
        .parse(input)
}

fn parse_not(input: &str) -> IResult<&str, Expr> {
    tag("not")
        .and(space1)
        .and(expr)
        .map(|(_, e)| Expr::Not(Box::new(e)))
        .parse(input)
}

fn parse_threshold(input: &str) -> IResult<&str, Expr> {
    tag("threshold")
        .and(space1)
        .and(parse_u32)
        .and(space1)
        .and(separated_list0(space1, expr))
        .map(|(((_, k), _), subs)| Expr::Threshold { k, subs })
        .parse(input)
}

fn parse_weighted_threshold(input: &str) -> IResult<&str, Expr> {
    tag("weighted-threshold")
        .and(space1)
        .and(parse_u32)
        .and(space1)
        .and(separated_list0(space1, weighted_sub))
        .map(|(((_, k), _), subs)| Expr::WeightedThreshold { k, subs })
        .parse(input)
}

fn weighted_sub(input: &str) -> IResult<&str, (Expr, u32)> {
    delimited(
        preceded(multispace0, char('(')),
        key_expr
            .and(space1)
            .and(parse_u32)
            .map(|((expr, _), weight)| (expr, weight)),
        preceded(multispace0, char(')')),
    )
    .parse(input)
}

/// ======= Testing =======

fn process_expr(expr: &Expr, depth: usize) {
    let indent = "  ".repeat(depth);
    match expr {
        Expr::Key(key) => println!("{}Key: {}", indent, key),
        Expr::And(exprs) => {
            println!("{}AND:", indent);
            for e in exprs {
                process_expr(e, depth + 1);
            }
        }
        Expr::Or(exprs) => {
            println!("{}OR:", indent);
            for e in exprs {
                process_expr(e, depth + 1);
            }
        }
        Expr::Not(e) => {
            println!("{}NOT:", indent);
            process_expr(e, depth + 1);
        }
        Expr::Threshold { k, subs } => {
            println!("{}Threshold {}:", indent, k);
            for e in subs {
                process_expr(e, depth + 1);
            }
        }
        Expr::WeightedThreshold { k, subs } => {
            println!("{}Weighted Threshold {}:", indent, k);
            for (e, w) in subs {
                println!("{}Weight {}:", indent, w);
                process_expr(e, depth + 1);
            }
        }
    }
}

fn main() {
    let tests = [
        "(and A B)",
        "(or (and A B) (not C))",
        "(and (or A B) (not D))",
        "(threshold 2 A B C)",
        "(weighted-threshold 3 (A 2) (B 1) (C 1))",
    ];

    for t in &tests {
        match expr(t) {
            Ok((rest, e)) if rest.trim().is_empty() => {
                println!("\nInput: {t}");
                println!("\nProcessed AST:");
                process_expr(&e, 0);
                println!("\nRaw AST: {:#?}", e);
            }
            Ok((rest, _)) => eprintln!("Unparsed rest: {:?}", rest),
            Err(err) => eprintln!("Parse error: {:?}", err),
        }
    }

    // Example of using methods from examples module
    if let Ok((_, expr)) = expr("(weighted-threshold 3 (A 2) (B 1) (C 1))") {
        println!("\nAnalyzing weighted threshold expression:");
        println!("All keys: {:?}", expr.get_all_keys());
        println!("Weight of A: {}", expr.get_key_weight("A"));
        println!("Contains key B? {}", expr.contains_key("B"));
        println!("Contains key D? {}", expr.contains_key("D"));
    }
}
