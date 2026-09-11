use std::borrow::Cow;
use std::path::PathBuf;

use clap::Parser;
use nos_cli::command::Command;
use nos_cli::{client, format};
use reedline::{Prompt, PromptEditMode, PromptHistorySearch, Reedline, Signal};

#[derive(Parser)]
#[command(name = "nos", about = "NOS interactive shell")]
struct Args {
    /// Path to the nos-configd IPC Unix socket.
    #[arg(long, default_value = "/run/nos/config.sock")]
    config_socket: PathBuf,
}

struct NosPrompt;

impl Prompt for NosPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed("nos")
    }

    fn render_prompt_right(&self) -> Cow<'_, str> {
        Cow::Borrowed("")
    }

    fn render_prompt_indicator(&self, _mode: PromptEditMode) -> Cow<'_, str> {
        Cow::Borrowed("> ")
    }

    fn render_prompt_multiline_indicator(&self) -> Cow<'_, str> {
        Cow::Borrowed(":::  ")
    }

    fn render_prompt_history_search_indicator(&self, _search: PromptHistorySearch) -> Cow<'_, str> {
        Cow::Borrowed("(search)> ")
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut line_editor = Reedline::create();
    let prompt = NosPrompt;

    println!("NOS interactive shell. Type 'help' for available commands.");

    loop {
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => match Command::parse(&line) {
                Command::Empty => {}
                Command::ShowConfig => {
                    match client::fetch_running_config(&args.config_socket).await {
                        Ok(cfg) => println!("{}", format::render_config(&cfg)),
                        Err(e) => eprintln!("error: {e}"),
                    }
                }
                Command::Help => print_help(),
                Command::Exit => break,
                Command::Unknown(cmd) => {
                    eprintln!("unknown command: '{cmd}' (type 'help' for a list of commands)");
                }
            },
            Ok(Signal::CtrlC | Signal::CtrlD) => break,
            Ok(_) => {}
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        }
    }

    Ok(())
}

fn print_help() {
    println!("Available commands:");
    println!("  show config   Print the running configuration from nos-configd");
    println!("  help          Show this help message");
    println!("  exit, quit    Exit the shell");
}
