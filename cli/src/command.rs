/// A parsed REPL input line.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    ShowConfig,
    Save,
    Help,
    Exit,
    Empty,
    Unknown(String),
}

impl Command {
    pub fn parse(line: &str) -> Self {
        let trimmed = line.trim();
        match trimmed.split_whitespace().collect::<Vec<_>>().as_slice() {
            [] => Command::Empty,
            ["show", "config"] => Command::ShowConfig,
            ["save"] => Command::Save,
            ["help"] => Command::Help,
            ["exit" | "quit"] => Command::Exit,
            _ => Command::Unknown(trimmed.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Command;

    #[test]
    fn show_config() {
        assert_eq!(Command::parse("show config"), Command::ShowConfig);
    }

    #[test]
    fn show_config_extra_whitespace() {
        assert_eq!(Command::parse("  show   config  "), Command::ShowConfig);
    }

    #[test]
    fn save() {
        assert_eq!(Command::parse("save"), Command::Save);
    }

    #[test]
    fn help() {
        assert_eq!(Command::parse("help"), Command::Help);
    }

    #[test]
    fn exit_and_quit() {
        assert_eq!(Command::parse("exit"), Command::Exit);
        assert_eq!(Command::parse("quit"), Command::Exit);
    }

    #[test]
    fn empty_line() {
        assert_eq!(Command::parse(""), Command::Empty);
        assert_eq!(Command::parse("   "), Command::Empty);
    }

    #[test]
    fn unknown_command() {
        assert_eq!(
            Command::parse("show interfaces"),
            Command::Unknown("show interfaces".to_string())
        );
    }
}
