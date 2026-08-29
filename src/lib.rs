pub mod cli;
pub mod core;
pub mod tui;

pub fn sanitize_terminal(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\n' || character == '\t' || !character.is_control() {
            output.push(character);
        } else {
            output.extend(character.escape_default());
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_text_escapes_control_sequences() {
        let input = format!("safe{}[31munsafe", char::from(27));
        assert_eq!(sanitize_terminal(&input), "safe\\u{1b}[31munsafe");
    }
}
