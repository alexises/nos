use std::borrow::Cow;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use clap::Parser;
use nos_cli::command::Command;
use nos_cli::session::{self, Mode, PathAfter, Resolved};
use nos_cli::{client, format};
use nos_proto::ConfigOp;
use reedline::{Prompt, PromptEditMode, PromptHistorySearch, Reedline, Signal};

#[derive(Parser)]
#[command(name = "nos", about = "NOS interactive shell")]
struct Args {
    /// Path to the nos-configd IPC Unix socket.
    #[arg(long, default_value = "/run/nos/config.sock")]
    config_socket: PathBuf,
}

struct NosPrompt {
    left: String,
}

impl NosPrompt {
    fn for_mode(mode: &Mode) -> Self {
        let left = match mode {
            Mode::Operational => "nos".to_string(),
            Mode::Configuration {
                transaction,
                path: session::Path::Root,
                ..
            } => format!("nos({transaction})"),
            Mode::Configuration {
                transaction,
                path: session::Path::BgpInstance(name),
                ..
            } => format!("nos({transaction}/bgp:{name})"),
        };
        Self { left }
    }
}

impl Prompt for NosPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.left)
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

/// Extracts the current transaction name — only ever called on a `Resolved`
/// variant that `session::resolve` only produces from `Mode::Configuration`.
fn current_transaction(mode: &Mode) -> String {
    match mode {
        Mode::Configuration { transaction, .. } => transaction.clone(),
        Mode::Operational => {
            unreachable!("resolve() only yields this action in Configuration mode")
        }
    }
}

fn current_path(mode: &Mode) -> session::Path {
    match mode {
        Mode::Configuration { path, .. } => path.clone(),
        Mode::Operational => {
            unreachable!("resolve() only yields this action in Configuration mode")
        }
    }
}

/// What the REPL loop should do after handling one resolved action.
enum Outcome {
    Continue(Mode),
    Exit,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut line_editor = Reedline::create();
    let mut mode = Mode::Operational;

    println!("NOS interactive shell. Type 'help' for available commands.");

    loop {
        let prompt = NosPrompt::for_mode(&mode);
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                let action = session::resolve(&mode, Command::parse(&line));
                match handle_action(action, mode, &args.config_socket).await {
                    Outcome::Continue(next_mode) => mode = next_mode,
                    Outcome::Exit => break,
                }
            }
            Ok(Signal::CtrlC | Signal::CtrlD) => {
                if let Mode::Configuration { transaction, .. } = &mode {
                    println!(
                        "transaction '{transaction}' left open on the daemon — resume with 'configure {transaction}'"
                    );
                }
                break;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_action(action: Resolved, mode: Mode, socket: &Path) -> Outcome {
    match action {
        Resolved::Nothing => Outcome::Continue(mode),
        Resolved::Help => {
            print_help();
            Outcome::Continue(mode)
        }
        Resolved::ExitShell => Outcome::Exit,
        Resolved::LeaveConfigPrompt => Outcome::Continue(handle_leave_prompt(mode, socket).await),
        Resolved::NavigateTop => Outcome::Continue(navigate_top(&mode)),
        Resolved::ShowRunningConfig => {
            show_running_config(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowTransaction => {
            show_transaction(&mode, socket).await;
            Outcome::Continue(mode)
        }
        Resolved::SaveRunningConfig => {
            save_running_config(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::OpenTransaction {
            name,
            base,
            explicit_base,
        } => Outcome::Continue(open_transaction(socket, name, base, explicit_base).await),
        Resolved::ApplyOp { op, after } => {
            Outcome::Continue(apply_op(mode, socket, op, after).await)
        }
        Resolved::Commit => Outcome::Continue(commit(mode, socket).await),
        Resolved::Discard => Outcome::Continue(discard(mode, socket).await),
        Resolved::Error(msg) => {
            eprintln!("error: {msg}");
            Outcome::Continue(mode)
        }
    }
}

enum LeaveChoice {
    Commit,
    Discard,
    LeaveOpen,
}

/// Blocking stdin prompt for what to do with an uncommitted transaction on
/// plain `exit`. Deliberately not a `reedline`-edited line — this is a
/// one-off yes/no-style question, not command input.
fn prompt_leave_choice(transaction: &str) -> LeaveChoice {
    loop {
        print!(
            "Transaction '{transaction}' has uncommitted changes. [c]ommit / [d]iscard / [l]eave open (default): "
        );
        if io::stdout().flush().is_err() {
            return LeaveChoice::LeaveOpen;
        }
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return LeaveChoice::LeaveOpen;
        }
        match input.trim().to_lowercase().as_str() {
            "c" | "commit" => return LeaveChoice::Commit,
            "d" | "discard" | "abort" => return LeaveChoice::Discard,
            "" | "l" | "leave" | "leave open" => return LeaveChoice::LeaveOpen,
            _ => println!("please enter c, d, or l"),
        }
    }
}

async fn handle_leave_prompt(mode: Mode, socket: &Path) -> Mode {
    let transaction = current_transaction(&mode);
    let dirty = matches!(&mode, Mode::Configuration { dirty: true, .. });
    if !dirty {
        return Mode::Operational;
    }
    match prompt_leave_choice(&transaction) {
        LeaveChoice::Commit => match client::commit_transaction(socket, &transaction).await {
            Ok(()) => {
                println!("transaction '{transaction}' committed");
                Mode::Operational
            }
            Err(e) => {
                eprintln!("error: {e} (transaction left open — fix and retry)");
                mode
            }
        },
        LeaveChoice::Discard => {
            if let Err(e) = client::discard_transaction(socket, &transaction).await {
                eprintln!("error: {e}");
            }
            Mode::Operational
        }
        LeaveChoice::LeaveOpen => {
            println!(
                "transaction '{transaction}' left open on the daemon — resume with 'configure {transaction}'"
            );
            Mode::Operational
        }
    }
}

fn navigate_top(mode: &Mode) -> Mode {
    let transaction = current_transaction(mode);
    let dirty = matches!(mode, Mode::Configuration { dirty: true, .. });
    Mode::Configuration {
        transaction,
        path: session::Path::Root,
        dirty,
    }
}

async fn show_running_config(socket: &Path) {
    match client::fetch_running_config(socket).await {
        Ok(cfg) => println!("{}", format::render_config(&cfg)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_transaction(mode: &Mode, socket: &Path) {
    let transaction = current_transaction(mode);
    let path = current_path(mode);
    match client::get_transaction(socket, &transaction).await {
        Ok(snap) => println!("{}", format::render_transaction(&snap, &path)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn save_running_config(socket: &Path) {
    match client::save_running_config(socket).await {
        Ok(()) => println!("configuration saved"),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn open_transaction(
    socket: &Path,
    name: String,
    base: nos_proto::TransactionBase,
    explicit_base: bool,
) -> Mode {
    match client::open_transaction(socket, &name, base).await {
        Ok(snap) => {
            if snap.resumed && explicit_base {
                println!(
                    "note: transaction '{name}' already exists with pending changes; resuming it and ignoring 'from ...'"
                );
            } else if snap.resumed {
                println!("resuming transaction '{name}'");
            }
            Mode::Configuration {
                transaction: name,
                path: session::Path::Root,
                dirty: snap.dirty,
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            Mode::Operational
        }
    }
}

async fn apply_op(mode: Mode, socket: &Path, op: ConfigOp, after: PathAfter) -> Mode {
    let transaction = current_transaction(&mode);
    let path = current_path(&mode);
    match client::apply_op(socket, &transaction, op).await {
        Ok(snap) => {
            let new_path = match after {
                PathAfter::Stay => path,
                PathAfter::ToRoot => session::Path::Root,
                PathAfter::To(p) => p,
            };
            Mode::Configuration {
                transaction,
                path: new_path,
                dirty: snap.dirty,
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            mode
        }
    }
}

async fn commit(mode: Mode, socket: &Path) -> Mode {
    let transaction = current_transaction(&mode);
    match client::commit_transaction(socket, &transaction).await {
        Ok(()) => {
            println!("transaction '{transaction}' committed");
            Mode::Operational
        }
        Err(e) => {
            eprintln!("error: {e} (transaction left open — fix and retry)");
            mode
        }
    }
}

async fn discard(mode: Mode, socket: &Path) -> Mode {
    let transaction = current_transaction(&mode);
    match client::discard_transaction(socket, &transaction).await {
        Ok(()) => {
            println!("transaction '{transaction}' discarded");
            Mode::Operational
        }
        Err(e) => {
            eprintln!("error: {e}");
            mode
        }
    }
}

fn print_help() {
    println!("Available commands:");
    println!("  show config                              Print the running configuration from nos-configd");
    println!(
        "  save                                      Persist the running configuration to disk"
    );
    println!("  configure <name> [from blank|current]     Enter configuration mode on a named transaction (default: current)");
    println!("  edit bgp instance <name>                  Create/navigate into a BGP instance");
    println!(
        "  set asn <n> | router-id <ip>               Set a field on the current BGP instance"
    );
    println!("  set bgp instance <name> asn <n>|router-id <ip>   Set a field on a named BGP instance from anywhere");
    println!(
        "  delete [bgp instance <name>]               Delete the current or a named BGP instance"
    );
    println!("  up, top                                    Navigate back to the transaction root");
    println!(
        "  show                                       Show the transaction (or current section)"
    );
    println!(
        "  commit                                     Validate and commit the current transaction"
    );
    println!("  discard, abort                             Discard the current transaction");
    println!("  help                                       Show this help message");
    println!(
        "  exit, quit, end                            Leave configuration mode, or exit the shell"
    );
}
