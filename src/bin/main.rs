use art_of_signature::parser::parse;

fn main() {
    let tests = [
        "(and A B)",
        "(or (and A B) (not C))",
        "(and (or A B) (not D))",
        "(threshold 2 A B C)",
        "(weighted-threshold 3 (A 2) (B 1) (C 1))",
    ];

    for t in &tests {
        match parse(t) {
            Ok((rest, e)) if rest.trim().is_empty() => {
                println!("\nInput: {t}");
                println!("\nRaw AST: {:#?}", e);
            }
            Ok((rest, _)) => eprintln!("Unparsed rest: {:?}", rest),
            Err(err) => eprintln!("Parse error: {:?}", err),
        }
    }
}
