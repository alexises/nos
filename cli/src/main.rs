use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, IsTerminal as _, Write as _};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::Context as _;
use clap::Parser;
use futures::StreamExt;
use nos_cli::command::Command;
use nos_cli::completer::NosCompleter;
use nos_cli::help_menu::HelpMenu;
use nos_cli::session::{self, Mode, PathAfter, Resolved};
use nos_cli::spec::{self, Doc};
use nos_cli::{
    bgp_client, client, format, interface_client, lacp_client, lldp_client, log_client,
    ospf_client, ospfv3_client, rib_client, watchdog_client,
};
use nos_pki::Identity;
use nos_proto::{
    CommandDoc, ConfigOp, Event, LogEvent, PolicyDefinitionOp, ServiceRef, Topic,
    DEFAULT_CONFIG_SOCKET,
};
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
    /// Path to nos-watchdogd's broker socket, used to resolve nos-configd's
    /// current address and, for `show route`, a specific nos-ribd
    /// instance's address — rather than assuming a hardcoded default.
    #[arg(long, default_value = nos_proto::DEFAULT_WATCHDOG_SOCKET)]
    watchdog_socket: PathBuf,

    /// The public CA certificate `nos-watchdogd` publishes — the trust anchor
    /// every daemon connection is checked against. It authenticates the
    /// watchdog to this shell and grants nothing.
    #[arg(long, default_value = nos_proto::DEFAULT_PKI_CA)]
    pki_ca: PathBuf,
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
            Mode::Configuration {
                transaction,
                path: session::Path::BgpPeerGroup { instance, group },
                ..
            } => format!("({transaction}/bgp:{instance}/peer-group:{group})"),
            Mode::Configuration {
                transaction,
                path: session::Path::RoutingTable(name),
                ..
            } => format!("({transaction}/routing-table:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::OspfInstance(name),
                ..
            } => format!("({transaction}/ospf:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::OspfArea { instance, area_id },
                ..
            } => format!("({transaction}/ospf:{instance}/area:{area_id})"),
            Mode::Configuration {
                transaction,
                path:
                    session::Path::OspfProfile {
                        instance,
                        area_id,
                        name,
                    },
                ..
            } => format!("({transaction}/ospf:{instance}/area:{area_id}/profile:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::Ospfv3Instance(name),
                ..
            } => format!("({transaction}/ospfv3:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::Ospfv3Area { instance, area_id },
                ..
            } => format!("({transaction}/ospfv3:{instance}/area:{area_id})"),
            Mode::Configuration {
                transaction,
                path:
                    session::Path::Ospfv3Profile {
                        instance,
                        area_id,
                        name,
                    },
                ..
            } => format!("({transaction}/ospfv3:{instance}/area:{area_id}/profile:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::StaticRoutingInstance(name),
                ..
            } => format!("({transaction}/static-routing-instance:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::Interface(name),
                ..
            } => format!("({transaction}/interface:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::Subinterface { interface, tag },
                ..
            } => format!("({transaction}/interface:{interface}.{tag})"),
            Mode::Configuration {
                transaction,
                path: session::Path::PolicyDefinition(name),
                ..
            } => format!("({transaction}/policy-definition:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::CommunityAlias(name),
                ..
            } => format!("({transaction}/community-alias:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::CommunityGroup(name),
                ..
            } => format!("({transaction}/community-group:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::PrefixList(name),
                ..
            } => format!("({transaction}/prefix-list:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::BroadcastDomain(name),
                ..
            } => format!("({transaction}/broadcast-domain:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::SwitchingProfile(name),
                ..
            } => format!("({transaction}/switching-profile:{name})"),
            Mode::Configuration {
                transaction,
                path: session::Path::PortAggregate(name),
                ..
            } => format!("({transaction}/port-aggregate:{name})"),
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
fn completer_for(socket: &Path, cache: DocCache, mode: &Mode) -> Box<dyn Completer + Send> {
    let doc_socket = socket.to_path_buf();
    let doc_source: Box<dyn FnMut(Topic) -> CommandDoc + Send> =
        Box::new(move |topic| doc_for_blocking(&doc_socket, &cache, topic));

    let instance_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
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

    // Deliberately flat/global — not scoped to whichever instance name is
    // already typed on the line — consistent with peer-group names being
    // unique across the whole config, not just within one instance (see
    // `nos_proto::schema::bgp_peer_group`).
    let peer_group_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .bgp_instances
                        .into_iter()
                        .flat_map(|i| i.peer_groups)
                        .map(|g| g.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    let routing_table_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .routing_tables
                        .into_iter()
                        .map(|t| t.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        // `show route <table>` needs table-name completion in operational
        // mode too, where there's no open transaction to read from — fall
        // back to the running config instead.
        Mode::Operational => {
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::fetch_running_config(&socket))
                })
                .map(|cfg| cfg.routing_tables.into_iter().map(|t| t.name).collect())
                .unwrap_or_default()
            })
        }
    };

    let ospf_instance_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .ospf_instances
                        .into_iter()
                        .map(|i| i.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    let static_routing_instance_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .static_routing_instances
                        .into_iter()
                        .map(|i| i.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    let interface_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| snap.config.interfaces.into_iter().map(|i| i.name).collect())
                .unwrap_or_default()
            })
        }
        // `show interface <name>` needs name completion in operational mode
        // too, where there's no open transaction to read from — fall back
        // to the running config instead, mirroring `routing_table_name_source`.
        Mode::Operational => {
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::fetch_running_config(&socket))
                })
                .map(|cfg| cfg.interfaces.into_iter().map(|i| i.name).collect())
                .unwrap_or_default()
            })
        }
    };

    let broadcast_domain_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .broadcast_domains
                        .into_iter()
                        .map(|d| d.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    let switching_profile_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .switching_profiles
                        .into_iter()
                        .map(|p| p.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    let port_aggregate_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .port_aggregates
                        .into_iter()
                        .map(|a| a.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    // Deliberately flat/global, flattened across every instance's areas —
    // not scoped to whichever instance/area is already typed on the line —
    // mirrors `peer_group_name_source`'s own reasoning, since profile names
    // are unique across the whole config (see
    // `nos_proto::schema::ospf_profile`).
    let ospf_profile_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .ospf_instances
                        .into_iter()
                        .flat_map(|i| i.areas)
                        .flat_map(|a| a.profiles)
                        .map(|p| p.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    let ospfv3_instance_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .ospfv3_instances
                        .into_iter()
                        .map(|i| i.name)
                        .collect()
                })
                .unwrap_or_default()
            })
        }
        Mode::Operational => Box::new(Vec::new),
    };

    // Deliberately flat/global, mirroring `ospf_profile_name_source`'s own
    // reasoning.
    let ospfv3_profile_name_source: Box<dyn FnMut() -> Vec<String> + Send> = match mode {
        Mode::Configuration { transaction, .. } => {
            let transaction = transaction.clone();
            let socket = socket.to_path_buf();
            Box::new(move || {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(client::get_transaction(&socket, &transaction))
                })
                .map(|snap| {
                    snap.config
                        .ospfv3_instances
                        .into_iter()
                        .flat_map(|i| i.areas)
                        .flat_map(|a| a.profiles)
                        .map(|p| p.name)
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
        peer_group_name_source,
        routing_table_name_source,
        ospf_instance_name_source,
        static_routing_instance_name_source,
        interface_name_source,
        broadcast_domain_name_source,
        switching_profile_name_source,
        ospf_profile_name_source,
        ospfv3_instance_name_source,
        ospfv3_profile_name_source,
        port_aggregate_name_source,
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

    // Trust the watchdog's CA, log in through it (it checks the password and
    // certifies a key we generate here), and only then talk to any daemon.
    let ca = std::fs::read(&args.pki_ca).with_context(|| {
        format!(
            "cannot read the ipc trust anchor {} — is nos-watchdogd running, with its /run/nos shared with this shell?",
            args.pki_ca.display()
        )
    })?;
    let identity = Identity::anonymous_from_pem(&ca).context("the ipc trust anchor is unusable")?;
    nos_pki::install(identity.clone());
    login(&args.watchdog_socket, &identity).await?;
    let config_socket = resolve_config_socket(&args.watchdog_socket).await;

    let completion_menu = ColumnarMenu::default().with_name("completion_menu");
    let mut line_editor = Reedline::create()
        .with_completer(completer_for(&config_socket, doc_cache.clone(), &mode))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(completion_menu)))
        .with_menu(ReedlineMenu::EngineCompleter(Box::new(HelpMenu::new())))
        .with_edit_mode(Box::new(Emacs::new(keybindings())));

    let hostname = Arc::new(Mutex::new(FALLBACK_HOSTNAME.to_string()));
    match client::fetch_running_config(&config_socket).await {
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
        config_socket.clone(),
        hostname.clone(),
        notify_repaint,
    ));

    println!("NOS interactive shell. Type 'help' for available commands, or press '?' at any point while typing.");

    loop {
        let prompt = NosPrompt::for_mode(hostname.clone(), &mode);
        match line_editor.read_line(&prompt) {
            Ok(Signal::Success(line)) => {
                let action = session::resolve(&mode, Command::parse(&line));
                match handle_action(
                    action,
                    mode,
                    &config_socket,
                    &args.watchdog_socket,
                    &doc_cache,
                )
                .await
                {
                    Outcome::Continue(next_mode) => mode = next_mode,
                    Outcome::Exit => break,
                }
                line_editor = line_editor.with_completer(completer_for(
                    &config_socket,
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

/// How many wrong username/password pairs are tolerated before the shell exits.
const LOGIN_ATTEMPTS: usize = 3;

/// Prompts for a username and password (no echo) and logs in through
/// `nos-watchdogd`: it checks them against the running config's users and, if
/// they match, certifies a key generated here — the certificate is held in
/// memory only and renewed in the background. Fails closed: with the watchdog
/// unreachable there is nobody to authenticate to, so the shell refuses to
/// start. The password check no longer happens in this process at all, and the
/// password hashes never leave the daemons.
async fn login(watchdog_socket: &Path, identity: &Identity) -> anyhow::Result<()> {
    for _ in 0..LOGIN_ATTEMPTS {
        print!("login: ");
        std::io::stdout().flush()?;
        let mut name = String::new();
        if std::io::stdin().read_line(&mut name)? == 0 {
            anyhow::bail!("no login supplied");
        }
        let name = name.trim();
        let password = rpassword::prompt_password("password: ")?;
        let (csr, key) = nos_pki::generate_csr()?;
        match watchdog_client::login(watchdog_socket, name, &password, csr).await {
            Ok(issued) => {
                identity.set_certificate(issued.cert_der, key)?;
                keep_certificate_fresh(
                    watchdog_socket.to_path_buf(),
                    identity.clone(),
                    issued.lifetime,
                );
                return Ok(());
            }
            Err(watchdog_client::WatchdogClientError::Denied(_)) => eprintln!("login incorrect"),
            Err(e) => anyhow::bail!("cannot log in: {e}"),
        }
    }
    anyhow::bail!("too many failed login attempts")
}

/// Renews the session's certificate at half its lifetime, with no password
/// (the still-valid certificate is the proof), retrying every 30s if the
/// watchdog can't be reached.
// ponytail: if renewal keeps failing until the certificate expires, commands
// start failing with connection errors and the user restarts the shell. A
// re-prompt for the password instead would need the prompt owned by the loop.
fn keep_certificate_fresh(
    watchdog_socket: PathBuf,
    identity: Identity,
    lifetime: std::time::Duration,
) {
    const RETRY: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::spawn(async move {
        let mut next = lifetime;
        loop {
            tokio::time::sleep(next / 2).await;
            let renewed = async {
                let (csr, key) = nos_pki::generate_csr().ok()?;
                let issued = watchdog_client::renew(&watchdog_socket, csr).await.ok()?;
                identity.set_certificate(issued.cert_der, key).ok()?;
                Some(issued.lifetime)
            }
            .await;
            next = renewed.unwrap_or(RETRY);
        }
    });
}

/// Resolves nos-configd's address via nos-watchdogd's broker, once at
/// startup. On any failure (broker unreachable, or it reports the service as
/// unavailable) falls back to the conventional default socket path and warns
/// — preserving the shell's existing resilience property that startup never
/// blocks or fails just because a daemon is briefly unreachable.
async fn resolve_config_socket(watchdog_socket: &Path) -> PathBuf {
    match watchdog_client::resolve(watchdog_socket, ServiceRef::Config).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!(
                "warning: nos-watchdogd reports nos-configd as unavailable; falling back to {DEFAULT_CONFIG_SOCKET}"
            );
            PathBuf::from(DEFAULT_CONFIG_SOCKET)
        }
        Err(e) => {
            eprintln!(
                "warning: could not resolve nos-configd via nos-watchdogd ({e}); falling back to {DEFAULT_CONFIG_SOCKET}"
            );
            PathBuf::from(DEFAULT_CONFIG_SOCKET)
        }
    }
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
    watchdog_socket: &Path,
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
        Resolved::Navigate(path) => Outcome::Continue(navigate_to(&mode, path)),
        Resolved::ShowRunningConfig => {
            show_running_config(socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowTransaction => {
            show_transaction(&mode, socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowRoute { table, address } => {
            show_route(watchdog_socket, &table, address).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowInterface { name } => {
            show_interface(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowPortAggregate { name } => {
            show_port_aggregate(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLacp { name } => {
            show_lacp(watchdog_socket, name.as_deref()).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLldpNeighbors => {
            show_lldp_neighbors(watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowLog { source, follow } => {
            show_log(watchdog_socket, source, follow).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowBgpBrief => {
            show_bgp_brief(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfNeigh => {
            show_ospf_neigh(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfDatabase => {
            show_ospf_database(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Neigh => {
            show_ospfv3_neigh(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ShowOspfv3Database => {
            show_ospfv3_database(socket, watchdog_socket).await;
            Outcome::Continue(mode)
        }
        Resolved::ClearBgpSoftIn { instance, peer } => {
            clear_bgp_soft_in(socket, watchdog_socket, &instance, peer).await;
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
        Resolved::EditPolicySource { name } => {
            Outcome::Continue(edit_policy_source(mode, socket, name).await)
        }
        Resolved::ShowPolicySource { name } => {
            show_policy_source(&mode, socket, &name).await;
            Outcome::Continue(mode)
        }
        Resolved::SetPolicySourceLine { name, line, text } => {
            let mode = edit_policy_source_line(mode, socket, name, |lines| {
                if line == 0 {
                    return Err("line numbers start at 1".to_string());
                }
                if line <= lines.len() {
                    lines[line - 1] = text;
                } else if line == lines.len() + 1 {
                    lines.push(text);
                } else {
                    return Err(format!(
                        "line {line} is out of range (source has {} lines; use {} to append)",
                        lines.len(),
                        lines.len() + 1
                    ));
                }
                Ok(())
            })
            .await;
            Outcome::Continue(mode)
        }
        Resolved::DeletePolicySourceLine { name, line } => {
            let mode = edit_policy_source_line(mode, socket, name, |lines| {
                if line == 0 || line > lines.len() {
                    return Err(format!(
                        "line {line} is out of range (source has {} lines)",
                        lines.len()
                    ));
                }
                lines.remove(line - 1);
                Ok(())
            })
            .await;
            Outcome::Continue(mode)
        }
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

fn navigate_to(mode: &Mode, path: session::Path) -> Mode {
    let transaction = current_transaction(mode);
    let dirty = matches!(mode, Mode::Configuration { dirty: true, .. });
    Mode::Configuration {
        transaction,
        path,
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

/// Resolves `table`'s nos-ribd instance fresh (not cached — tables come and
/// go during a session) via the watchdog broker, then queries it either for
/// the whole table (`address: None`) or a longest-prefix-match lookup.
async fn show_route(watchdog_socket: &Path, table: &str, address: Option<std::net::IpAddr>) {
    let rib_socket = match watchdog_client::resolve(
        watchdog_socket,
        nos_proto::ServiceRef::RibTable(table.to_string()),
    )
    .await
    {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("routing table '{table}' is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    match address {
        None => match rib_client::get_routes(&rib_socket).await {
            Ok(routes) => println!("{}", format::render_prefix_routes(&routes)),
            Err(e) => eprintln!("error: {e}"),
        },
        Some(addr) => match rib_client::lookup(&rib_socket, addr).await {
            Ok(Some(matched)) => println!("{}", format::render_prefix_routes(&[matched])),
            Ok(None) => println!("no route matches {addr}"),
            Err(e) => eprintln!("error: {e}"),
        },
    }
}

/// Resolves the single `nos-interfaced` instance fresh (not cached — it's
/// still just one dial per command, matching `show_route`'s convention) via
/// the watchdog broker, then queries it either for every interface
/// (`name: None`) or one named interface.
async fn show_interface(watchdog_socket: &Path, name: Option<&str>) {
    let interface_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Interfaces).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-interfaced is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match name {
        None => match interface_client::get_interfaces(&interface_socket).await {
            Ok(statuses) => println!("{}", format::render_interface_statuses(&statuses)),
            Err(e) => eprintln!("error: {e}"),
        },
        Some(name) => match interface_client::get_interface(&interface_socket, name).await {
            Ok(Some(status)) => println!("{}", format::render_interface_statuses(&[status])),
            Ok(None) => println!("interface '{name}' not found"),
            Err(e) => eprintln!("error: {e}"),
        },
    }
}

/// Same resolution and shape as `show_interface`, against `nos-interfaced`'s
/// port-aggregate query instead.
async fn show_lacp(watchdog_socket: &Path, name: Option<&str>) {
    let lacp_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Lacp).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-lacpd is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match lacp_client::get_summary(&lacp_socket).await {
        Ok(summaries) => match name {
            None => println!("{}", format::render_lacp_summaries(&summaries)),
            Some(name) => {
                let one: Vec<_> = summaries
                    .into_iter()
                    .filter(|s| s.aggregate == name)
                    .collect();
                if one.is_empty() {
                    println!("lacp port aggregate '{name}' not found");
                } else {
                    println!("{}", format::render_lacp_summaries(&one));
                }
            }
        },
        Err(e) => eprintln!("error: {e}"),
    }
}

/// Same resolution and shape as `show_lacp`, against `nos-lldpd`'s neighbor
/// query.
async fn show_lldp_neighbors(watchdog_socket: &Path) {
    let lldp_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Lldp).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-lldpd is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match lldp_client::get_neighbors(&lldp_socket).await {
        Ok(neighbors) => println!("{}", format::render_lldp_neighbors(&neighbors)),
        Err(e) => eprintln!("error: {e}"),
    }
}

async fn show_port_aggregate(watchdog_socket: &Path, name: Option<&str>) {
    let interface_socket =
        match watchdog_client::resolve(watchdog_socket, nos_proto::ServiceRef::Interfaces).await {
            Ok(Some(path)) => path,
            Ok(None) => {
                eprintln!("nos-interfaced is not running");
                return;
            }
            Err(e) => {
                eprintln!("error: {e}");
                return;
            }
        };

    match name {
        None => match interface_client::get_port_aggregates(&interface_socket).await {
            Ok(statuses) => println!("{}", format::render_port_aggregate_statuses(&statuses)),
            Err(e) => eprintln!("error: {e}"),
        },
        Some(name) => match interface_client::get_port_aggregate(&interface_socket, name).await {
            Ok(Some(status)) => println!("{}", format::render_port_aggregate_statuses(&[status])),
            Ok(None) => println!("port aggregate '{name}' not found"),
            Err(e) => eprintln!("error: {e}"),
        },
    }
}

/// Resolves the single `nos-logd` instance fresh (not cached, matching
/// `show_route`/`show_interface`'s convention) via the watchdog broker, then
/// either prints a one-shot buffer snapshot or streams a live tail until the
/// user presses Ctrl-C or the connection is lost.
async fn show_log(watchdog_socket: &Path, source: Option<String>, follow: bool) {
    let log_socket = match watchdog_client::resolve(watchdog_socket, ServiceRef::Log).await {
        Ok(Some(path)) => path,
        Ok(None) => {
            eprintln!("nos-logd is not running");
            return;
        }
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if !follow {
        match log_client::get_logs(&log_socket, source, None).await {
            Ok(logs) => println!("{}", format::render_log_entries(&logs)),
            Err(e) => eprintln!("error: {e}"),
        }
        return;
    }

    let mut reader = match log_client::tail(&log_socket, source).await {
        Ok(reader) => reader,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    println!("-- following nos-logd, press Ctrl-C to stop --");
    loop {
        tokio::select! {
            event = reader.next() => match event {
                Some(Ok(LogEvent::Logs(logs))) => println!("{}", format::render_log_entries(&logs)),
                Some(Ok(LogEvent::Line(entry))) => println!("{}", format::render_log_entry(&entry)),
                Some(Ok(LogEvent::Error(msg))) => {
                    eprintln!("error: {msg}");
                    break;
                }
                Some(Err(e)) => {
                    eprintln!("error: {e}");
                    break;
                }
                None => {
                    eprintln!("connection to nos-logd closed");
                    break;
                }
            },
            _ = tokio::signal::ctrl_c() => {
                println!();
                break;
            }
        }
    }
}

/// Router-wide, no instance argument: fetches the running config fresh (like
/// every other one-shot command) for the list of configured `BgpInstance`s,
/// resolves each one's `nos-bgpd` via the watchdog broker, and queries each
/// independently — an unreachable instance prints its own line rather than
/// aborting the whole command, matching `show_route`/`show_interface`'s
/// per-command resolve-then-query shape.
async fn show_bgp_brief(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.bgp_instances.is_empty() {
        println!("no bgp instances configured");
        return;
    }

    for instance in &cfg.bgp_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::BgpInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(bgp_socket)) => match bgp_client::get_summary(&bgp_socket).await {
                Ok(peers) => println!("{}", format::render_bgp_summary(&instance.name, &peers)),
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("bgp instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospf neigh` — fetches the running config for the list of
/// `OspfInstance`s, resolves each one's `nos-ospfd` via the watchdog broker,
/// and queries each independently — mirrors `show_bgp_brief` exactly,
/// including its per-instance "not running" handling.
async fn show_ospf_neigh(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospf_instances.is_empty() {
        println!("no ospf instances configured");
        return;
    }

    for instance in &cfg.ospf_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::OspfInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospf_socket)) => match ospf_client::get_neighbors(&ospf_socket).await {
                Ok(neighbors) => {
                    println!(
                        "{}",
                        format::render_ospf_neighbors(&instance.name, &neighbors)
                    );
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospf database` — mirrors `show_ospf_neigh` exactly, one instance at
/// a time, reporting a not-running instance individually rather than
/// aborting the whole command.
async fn show_ospf_database(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospf_instances.is_empty() {
        println!("no ospf instances configured");
        return;
    }

    for instance in &cfg.ospf_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::OspfInstance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospf_socket)) => match ospf_client::get_database(&ospf_socket).await {
                Ok(entries) => {
                    println!("{}", format::render_ospf_database(&instance.name, &entries));
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospf instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospfv3 neigh` — mirrors `show_ospf_neigh` exactly, over every
/// configured `Ospfv3Instance`.
async fn show_ospfv3_neigh(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospfv3_instances.is_empty() {
        println!("no ospfv3 instances configured");
        return;
    }

    for instance in &cfg.ospfv3_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::Ospfv3Instance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospfv3_socket)) => match ospfv3_client::get_neighbors(&ospfv3_socket).await {
                Ok(neighbors) => {
                    println!(
                        "{}",
                        format::render_ospfv3_neighbors(&instance.name, &neighbors)
                    );
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// `show ospfv3 database` — mirrors `show_ospf_database` exactly, over every
/// configured `Ospfv3Instance`.
async fn show_ospfv3_database(config_socket: &Path, watchdog_socket: &Path) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };

    if cfg.ospfv3_instances.is_empty() {
        println!("no ospfv3 instances configured");
        return;
    }

    for instance in &cfg.ospfv3_instances {
        match watchdog_client::resolve(
            watchdog_socket,
            nos_proto::ServiceRef::Ospfv3Instance(instance.name.clone()),
        )
        .await
        {
            Ok(Some(ospfv3_socket)) => match ospfv3_client::get_database(&ospfv3_socket).await {
                Ok(entries) => {
                    println!(
                        "{}",
                        format::render_ospfv3_database(&instance.name, &entries)
                    );
                }
                Err(e) => eprintln!("error: {e}"),
            },
            Ok(None) => println!("ospfv3 instance '{}' is not running", instance.name),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}

/// Targets one named instance (errors clearly if it isn't in the running
/// config), unlike `show_bgp_brief`'s all-instances loop.
async fn clear_bgp_soft_in(
    config_socket: &Path,
    watchdog_socket: &Path,
    instance: &str,
    peer: IpAddr,
) {
    let cfg = match client::fetch_running_config(config_socket).await {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return;
        }
    };
    if !cfg.bgp_instances.iter().any(|i| i.name == instance) {
        eprintln!("error: no bgp instance named '{instance}' in the running config");
        return;
    }

    match watchdog_client::resolve(
        watchdog_socket,
        nos_proto::ServiceRef::BgpInstance(instance.to_string()),
    )
    .await
    {
        Ok(Some(bgp_socket)) => match bgp_client::send_route_refresh(&bgp_socket, peer).await {
            Ok(true) => println!("route refresh requested for {peer}"),
            Ok(false) => eprintln!("error: no established session with {peer} on '{instance}'"),
            Err(e) => eprintln!("error: {e}"),
        },
        Ok(None) => println!("bgp instance '{instance}' is not running"),
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

/// Fetches the current transaction's source for `name` — `None` only on a
/// connection/IPC error (already reported to stderr), not on the policy
/// merely not existing (its source is just `""` then, since this is only
/// ever called while navigated into it, which requires it to exist).
async fn fetch_policy_source(socket: &Path, transaction: &str, name: &str) -> Option<String> {
    match client::get_transaction(socket, transaction).await {
        Ok(snap) => Some(
            snap.config
                .policy_definitions
                .iter()
                .find(|p| p.name == name)
                .map_or_else(String::new, |p| p.source.clone()),
        ),
        Err(e) => {
            eprintln!("error: {e}");
            None
        }
    }
}

/// Stages a new, already-compile-checked source for `name` — the check that
/// ran before this call is advisory/fast-feedback only; `nos-configd`'s
/// commit-time validation (via `PolicyDefinition`'s garde validator) stays
/// the authoritative gate, unchanged.
async fn apply_policy_source(mode: Mode, socket: &Path, name: String, source: String) -> Mode {
    apply_op(
        mode,
        socket,
        ConfigOp::PolicyDefinition(PolicyDefinitionOp::SetSource { name, source }),
        PathAfter::Stay,
    )
    .await
}

/// Opens `$EDITOR`/`$VISUAL`/`nano` on a temp file pre-filled with `source`
/// — see root `CLAUDE.md`'s "nos-cli editing UX". `None` means no editor
/// could be spawned at all (already reported to stderr); the caller should
/// point the user at `show source`/`set source line <n> <text>` instead.
fn edit_in_external_editor(source: &str) -> Option<String> {
    let editor = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| "nano".to_string());
    let path = std::env::temp_dir().join(format!("nos-policy-{}.rpl", std::process::id()));
    if std::fs::write(&path, source).is_err() {
        eprintln!("error: could not create a temp file for editing");
        return None;
    }
    let result = match std::process::Command::new(&editor).arg(&path).status() {
        Ok(status) if status.success() => std::fs::read_to_string(&path).ok(),
        Ok(_) => {
            eprintln!("editor '{editor}' exited with an error; edit discarded");
            None
        }
        Err(e) => {
            eprintln!(
                "error: could not run editor '{editor}' ({e}) — use 'show source' and 'set source line <n> <text>' instead"
            );
            None
        }
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// Compiles `source` against the current transaction's `community_aliases`/
/// `community_groups`/`prefix_lists`, so this advisory client-side check
/// (see `edit_policy_source`/`edit_policy_source_line`) doesn't spuriously
/// reject a script that references a real alias/group/prefix-list — the
/// authoritative gate stays `nos-configd`'s commit-time validation,
/// unchanged. `None` only on a connection/IPC error (already reported to
/// stderr), matching `fetch_policy_source`.
async fn compile_against_transaction(
    socket: &Path,
    transaction: &str,
    source: &str,
) -> Option<Result<(), nos_rpl::CompileError>> {
    let snap = match client::get_transaction(socket, transaction).await {
        Ok(snap) => snap,
        Err(e) => {
            eprintln!("error: {e}");
            return None;
        }
    };
    let cfg = &snap.config;

    // Owned, pre-resolved buffers backing the `nos_rpl::Symbols` view below
    // — see `nos_proto::schema::policy_definition::valid_source`/
    // `nos_bgp::policy::PolicyCache::resync` for the same adapter, written
    // once per consumer per this codebase's usual `to_policy_input`-style
    // idiom rather than shared.
    let alias_parts: Vec<(&str, Vec<i64>)> = cfg
        .community_aliases
        .iter()
        .filter_map(|a| {
            nos_rpl::parse_colon_literal(&a.value).map(|parts| (a.name.as_str(), parts))
        })
        .collect();
    let alias_refs: Vec<(&str, &[i64])> = alias_parts
        .iter()
        .map(|(n, p)| (*n, p.as_slice()))
        .collect();

    let resolve_member = |m: &str| -> Option<Vec<i64>> {
        cfg.community_aliases
            .iter()
            .find(|a| a.name == m)
            .and_then(|a| nos_rpl::parse_colon_literal(&a.value))
            .or_else(|| nos_rpl::parse_colon_literal(m))
    };
    let group_parts: Vec<(&str, Vec<Vec<i64>>)> = cfg
        .community_groups
        .iter()
        .map(|g| {
            (
                g.name.as_str(),
                g.members.iter().filter_map(|m| resolve_member(m)).collect(),
            )
        })
        .collect();
    let group_member_slices: Vec<Vec<&[i64]>> = group_parts
        .iter()
        .map(|(_, members)| members.iter().map(Vec::as_slice).collect())
        .collect();
    let group_refs: Vec<(&str, &[&[i64]])> = group_parts
        .iter()
        .zip(&group_member_slices)
        .map(|((name, _), slices)| (*name, slices.as_slice()))
        .collect();

    let prefix_list_entries: Vec<(&str, Vec<nos_rpl::PrefixListEntry>)> = cfg
        .prefix_lists
        .iter()
        .map(|pl| {
            let entries = pl
                .entries
                .iter()
                .map(|e| nos_rpl::PrefixListEntry {
                    cidr: e.cidr,
                    range: e.range,
                })
                .collect();
            (pl.name.as_str(), entries)
        })
        .collect();
    let prefix_list_refs: Vec<(&str, &[nos_rpl::PrefixListEntry])> = prefix_list_entries
        .iter()
        .map(|(n, e)| (*n, e.as_slice()))
        .collect();

    let symbols = nos_rpl::Symbols {
        aliases: &alias_refs,
        groups: &group_refs,
        prefix_lists: &prefix_list_refs,
    };

    Some(nos_rpl::compile(source, &symbols).map(|_| ()))
}

async fn edit_policy_source(mode: Mode, socket: &Path, name: String) -> Mode {
    let transaction = current_transaction(&mode);
    let Some(current) = fetch_policy_source(socket, &transaction, &name).await else {
        return mode;
    };
    let Some(edited) = edit_in_external_editor(&current) else {
        return mode;
    };
    match compile_against_transaction(socket, &transaction, &edited).await {
        Some(Ok(())) => apply_policy_source(mode, socket, name, edited).await,
        Some(Err(e)) => {
            eprintln!("policy did not compile, edit discarded: {e}");
            mode
        }
        None => mode,
    }
}

async fn show_policy_source(mode: &Mode, socket: &Path, name: &str) {
    let transaction = current_transaction(mode);
    if let Some(source) = fetch_policy_source(socket, &transaction, name).await {
        println!("{}", format::render_policy_source(&source));
    }
}

/// Shared by `set source line <n> <text>`/`delete source line <n>`: applies
/// `edit` to the current source's lines (1-indexed, matching `show
/// source`'s display), then runs the same client-side compile check `edit
/// source` does before staging it. `edit` reports an out-of-range line
/// itself, so both callers can just describe their own bounds rule.
async fn edit_policy_source_line(
    mode: Mode,
    socket: &Path,
    name: String,
    edit: impl FnOnce(&mut Vec<String>) -> Result<(), String>,
) -> Mode {
    let transaction = current_transaction(&mode);
    let Some(current) = fetch_policy_source(socket, &transaction, &name).await else {
        return mode;
    };
    let mut lines: Vec<String> = current.lines().map(str::to_string).collect();
    if let Err(e) = edit(&mut lines) {
        eprintln!("error: {e}");
        return mode;
    }
    let mut new_source = lines.join("\n");
    if !new_source.is_empty() {
        new_source.push('\n');
    }
    match compile_against_transaction(socket, &transaction, &new_source).await {
        Some(Ok(())) => apply_policy_source(mode, socket, name, new_source).await,
        Some(Err(e)) => {
            eprintln!("policy did not compile, edit discarded: {e}");
            mode
        }
        None => mode,
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
