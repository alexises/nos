use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use clap::Parser;
use futures::StreamExt;
use nos_cli::command::Command;
use nos_cli::completer::NosCompleter;
use nos_cli::help_menu::HelpMenu;
use nos_cli::session::{self, Mode, PathAfter, Resolved};
use nos_cli::spec::{self, Doc};
use nos_cli::{client, format};
use nos_proto::{CommandDoc, ConfigOp, Event, Topic};
use reedline::{
    default_emacs_keybindings, ColumnarMenu, Completer, Emacs, KeyCode, KeyModifiers, MenuBuilder,
    Prompt, PromptEditMode, PromptHistorySearch, Reedline, ReedlineEvent, ReedlineMenu, Signal,
};

/// Per-session cache of operation documentation fetched from `nos-configd`,
/// keyed by `Topic` — populated lazily, at most once per topic per session
/// (see `doc_for`/`doc_for_blocking`), never bulk-fetched up front.
type DocCache = Arc<Mutex<HashMap<Topic, CommandDoc>>>;

#[derive(Parser)]
#[command(name = "nos", about = "NOS interactive shell")]
struct Args {
    /// Path to the nos-configd IPC Unix socket.
    #[arg(long, default_value = "/run/nos/config.sock")]
    config_socket: PathBuf,
}

/// Placeholder shown until the daemon is reachable — see `subscribe_hostname_task`.
const FALLBACK_HOSTNAME: &str = "nos";

struct NosPrompt {
    hostname: Arc<Mutex<String>>,
    suffix: String,
}

impl NosPrompt {
    fn for_mode(hostname: Arc<Mutex<String>>, mode: &Mode) -> Self {
        let suffix = match mode {
            Mode::Operational => String::new(),
            Mode::Configuration {
                transaction,
                path: session::Path::Root,
                ..
            } => format!("({transaction})"),
            Mode::Configuration {
                transaction,
                path: session::Path::BgpInstance(name),
                ..
            } => format!("({transaction}/bgp:{name})"),
        };
        Self { hostname, suffix }
    }
}

impl Prompt for NosPrompt {
    fn render_prompt_left(&self) -> Cow<'_, str> {
        let hostname = self.hostname.lock().unwrap().clone();
        Cow::Owned(format!("{hostname}{}", self.suffix))
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

/// `?` and Tab both leave text insertion alone otherwise, so both need an
/// explicit keybinding on top of `default_emacs_keybindings()`: Tab opens
/// (or cycles) `completion_menu`, and `?` opens (or, on a second consecutive
/// press — see `help_menu::HelpMenu`) deepens `nos_help`. Both follow the
/// same `UntilFound([Menu(name), MenuNext-ish])` shape reedline's own docs
/// use for Tab — `ReedlineEvent::Menu(name)` only fires when no menu is
/// already active, so the second event in each pair is what a repeat press
/// falls through to.
fn keybindings() -> reedline::Keybindings {
    let mut keybindings = default_emacs_keybindings();
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Tab,
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("completion_menu".to_string()),
            ReedlineEvent::MenuNext,
        ]),
    );
    keybindings.add_binding(
        KeyModifiers::NONE,
        KeyCode::Char('?'),
        ReedlineEvent::UntilFound(vec![
            ReedlineEvent::Menu("nos_help".to_string()),
            ReedlineEvent::MenuPageNext,
        ]),
    );
    keybindings
}

/// Builds the completer for the *current* `mode` — called fresh each loop
/// iteration (mirroring `NosPrompt::for_mode`, already rebuilt every
/// iteration) so completions/`?`/`help` always reflect the mode the last
/// command actually landed in.
fn completer_for(socket: PathBuf, cache: DocCache, mode: &Mode) -> Box<dyn Completer + Send> {
    let doc_socket = socket.clone();
    let doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send> =
        Box::new(move |topic| doc_for_blocking(&doc_socket, &cache, topic));

    let instance_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .bgp_instances
                        .into_iter()
                        .map(|i| i.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    Box::new(NosCompleter::new(
        mode.clone(),
        doc_source,
        instance_name_source,
    ))
}

/// Cache-first lookup for a topic's documentation, from a synchronous
/// context (reedline's `Completer`/`Menu` callbacks aren't `async`). Blocks
/// on one IPC round trip only on a cache miss — see `DocCache`.
fn doc_for_blocking(socket: &Path, cache: &DocCache, topic: Topic) -> CommandDoc {
    if let Some(doc) = cache.lock().unwrap().get(&topic) {
        return doc.clone();
    }
    let fetched = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(client::describe(socket, topic))
    });
    match fetched {
        Ok(doc) => {
            cache.lock().unwrap().insert(topic, doc.clone());
            doc
        }
        Err(_) => unavailable_doc(topic),
    }
}

/// Cache-first lookup for a topic's documentation, from an `async` context
/// (used by `print_help`, which can simply `.await` rather than block).
async fn doc_for(socket: &Path, cache: &DocCache, topic: Topic) -> CommandDoc {
    if let Some(doc) = cache.lock().unwrap().get(&topic) {
        return doc.clone();
    }
    match client::describe(socket, topic).await {
        Ok(doc) => {
            cache.lock().unwrap().insert(topic, doc.clone());
            doc
        }
        Err(_) => unavailable_doc(topic),
    }
}

fn unavailable_doc(topic: Topic) -> CommandDoc {
    let text = "description unavailable — could not reach nos-configd".to_string();
    CommandDoc {
        topic,
        summary: text.clone(),
        detail: text,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut mode = Mode::Operational;
    let doc_cache: DocCache = Arc::new(Mutex::new(HashMap::new()));

    let completion_menu = ColumnarMenu::default().with_name("completion_menu");
    let mut line_editor = Reedline::create()
        .with_completer(completer_for(
            args.config_socket.clone(),
            doc_cache.clone(),
            &mode,
        ))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(completion_menu)))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(HelpMenu::new())))
        .with_edit_mode(Box::new(Emacs::new(keybindings())));

    let hostname = Arc::new(Mutex::new(FALLBACK_HOSTNAME.to_string()));
    match client::fetch_running_config(&args.config_socket).await {
        Ok(cfg) => *hostname.lock().unwrap() = cfg.hostname,
        Err(_) => eprintln!(
            "warning: could not reach nos-configd at startup; hostname prompt may be stale"
        ),
    }

    // `RepaintSignal` isn't reachable outside the reedline crate (its return
    // type here is public but its owning module isn't) — capture it in a
    // closure instead of naming it, so `subscribe_hostname_task` only needs
    // an `impl Fn()` bound.
    let repaint_signal = line_editor.repaint_signal();
    let notify_repaint = move || repaint_signal.request_repaint();
    tokio::spawn(subscribe_hostname_task(
        args.config_socket.clone(),
        hostname.clone(),
        notify_repaint,
    ));

    println!("NOS interactive shell. Type 'help' for available commands, or press '?' at any point while typing.");

    loop {
        let prompt = NosPrompt::for_mode(hostname.clone(), &mode);
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                let action = session::resolve(&mode, Command::parse(&line));
                match handle_action(action, mode, &args.config_socket, &doc_cache).await {
                    Outcome::Continue(next_mode) => mode = next_mode,
                    Outcome::Exit => break,
                }
                line_editor = line_editor.with_completer(completer_for(
                    args.config_socket.clone(),
                    doc_cache.clone(),
                    &mode,
                ));
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

/// Holds a long-lived `Request::Subscribe` connection for the shell's whole
/// lifetime, keeping `hostname` current and triggering an in-place prompt
/// repaint (via `RepaintSignal`) whenever it changes — including while the
/// shell is idle at the prompt, not just on the next command. Reconnects on
/// a fixed 1s delay after any disconnect/error; this is nos-cli's first
/// long-lived connection, so unlike every one-shot `client::*` call (which
/// simply reports its own error per command), leaving this unattended would
/// otherwise freeze the prompt's hostname for the rest of the session after
/// a daemon restart.
async fn subscribe_hostname_task(
    socket: PathBuf,
    hostname: Arc<Mutex<String>>,
    notify_repaint: impl Fn() + Send + 'static,
) {
    loop {
        if let Ok(mut reader) = client::subscribe(&socket).await {
            while let Some(Ok(Event::Config(cfg))) = reader.next().await {
                let mut guard = hostname.lock().unwrap();
                if *guard != cfg.hostname {
                    *guard = cfg.hostname;
                    drop(guard);
                    notify_repaint();
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn handle_action(
    action: Resolved,
    mode: Mode,
    socket: &Path,
    doc_cache: &DocCache,
) -> Outcome {
    match action {
        Resolved::Nothing => Outcome::Continue(mode),
        Resolved::Help => {
            print_help(&mode, socket, doc_cache).await;
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
        Resolved::Diff => {
            diff(&mode, socket).await;
            Outcome::Continue(mode)
        }
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

/// Whether to emit ANSI color/highlight codes for `diff`: only when stdout
/// is an actual terminal, and never when `NO_COLOR` is set (the informal
/// but widely-honored convention — <https://no-color.org>).
fn use_color() -> bool {
    io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

async fn diff(mode: &Mode, socket: &Path) {
    let transaction = current_transaction(mode);
    match client::diff_transaction(socket, &transaction).await {
        Ok(d) if d.is_empty() => println!("no changes"),
        Ok(d) => println!("{}", format::render_diff(&d, use_color())),
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

/// Lists every command valid in `mode` right now — the same filtering (and,
/// for server-backed commands, the same lazily-fetched, session-cached
/// text) that the live `?` key's brief mode uses. Equivalent to pressing
/// `?` on an empty line.
async fn print_help(mode: &Mode, socket: &Path, cache: &DocCache) {
    println!("Available commands:");
    for command in spec::COMMAND_SPECS {
        if !spec::availability_matches(command.availability, mode) {
            continue;
        }
        let summary = match &command.doc {
            Doc::Local { summary, .. } => (*summary).to_string(),
            Doc::FromConfig(topic) => doc_for(socket, cache, *topic).await.summary,
        };
        println!("  {:<45} {}", command.usage, summary);
    }
}
