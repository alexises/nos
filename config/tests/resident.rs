//! Live-heap check for the config store (#766/#767/#773): a counting global
//! allocator reports what one route `PUT` and one commit cost at ~66k static
//! routes with live diff subscribers, and bounds what stays live after
//! several commits (the broadcast ring included) and the subscribers' diffs
//! of each commit (#778).

#![allow(clippy::cast_precision_loss, reason = "printed ratios only")]
#![allow(
    unsafe_code,
    reason = "a GlobalAlloc impl is unsafe by definition; it only forwards to System"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use nos_config::ConfigStore;
use nos_proto::{Config, DiffScope, Event, Role, TransactionBase};
use tokio::sync::mpsc;

struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let now = LIVE.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(now, Relaxed);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- counting GlobalAlloc delegating to System
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- counting GlobalAlloc delegating to System
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_sub(l.size(), Relaxed);
        let now = LIVE.fetch_add(new, Relaxed) + new;
        PEAK.fetch_max(now, Relaxed);
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- counting GlobalAlloc delegating to System
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

const INSTANCES: u32 = 3;
const PER_INSTANCE: u32 = 22_000;
/// Commits measured after the seed, sharing the single-route PUTs between
/// them: 2000 by default (#772 Q6), `NOS_RESIDENT_PUTS` overrides.
const COMMITS: u32 = 4;

fn puts_per_commit() -> u32 {
    std::env::var("NOS_RESIDENT_PUTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000)
        .max(COMMITS)
        / COMMITS
}
/// Diff subscribers, one per visibility class kind: everything (`User`, also
/// `Restd`), users only (`Watchdog`), protocol keys (`Bgpd`).
const SUBSCRIBERS: [Role; 3] = [Role::User, Role::Watchdog, Role::Bgpd];

fn path(instance: u32) -> Vec<String> {
    vec!["static-routing-instance".into(), format!("sw{instance}")]
}

/// `100.64.0.0 + n` as a /32.
fn prefix(n: u32) -> String {
    let a = 0x6440_0000_u32 + n;
    format!(
        "{}.{}.{}.{}/32",
        a >> 24,
        (a >> 16) & 255,
        (a >> 8) & 255,
        a & 255
    )
}

fn route_json(n: u32) -> String {
    format!(r#"{{"subnet":"{}","gateway":"192.0.2.1"}}"#, prefix(n))
}

fn instance_json(instance: u32, routes: std::ops::Range<u32>) -> String {
    let routes: Vec<String> = routes.map(route_json).collect();
    format!(
        r#"{{"name":"sw{instance}","routes":[{}]}}"#,
        routes.join(",")
    )
}

/// Waits (bounded) for every subscriber's event of the last commit.
async fn drain(subs: &mut [mpsc::Receiver<Event>]) {
    for rx in subs {
        let ev = tokio::time::timeout(Duration::from_secs(120), rx.recv())
            .await
            .expect("diff subscriber timed out")
            .expect("diff subscriber closed");
        assert!(matches!(ev, Event::Diff(_)), "{ev:?}");
    }
}

#[tokio::test]
async fn commit_and_put_cost_at_66k_routes() {
    let store = ConfigStore::new(Config::default(), None);
    store
        .open_transaction("seed", TransactionBase::Blank)
        .await
        .unwrap();
    // Three list PUTs, not 66k single ones: the base load only has to exist.
    for i in 0..INSTANCES {
        let json = instance_json(i, i * PER_INSTANCE..(i + 1) * PER_INSTANCE);
        store
            .set_transaction_path("seed", &path(i), Some(&json), None, None)
            .await
            .unwrap();
    }
    store.commit_transaction("seed", None).await.unwrap();

    // One Config's own live size and its JSON size.
    let running = store.running_snapshot().await;
    let before_clone = LIVE.load(Relaxed);
    let copy = (*running).clone();
    let one_config = LIVE.load(Relaxed) - before_clone;
    drop(copy);
    let json_len = serde_json::to_vec(&*running).unwrap().len();
    drop(running);

    // Live diff subscribers, as nos-watchdogd/nos-bgpd/nos-restd hold them.
    let mut subs = Vec::new();
    let mut tasks = Vec::new();
    for role in SUBSCRIBERS {
        let (tx, rx) = mpsc::channel(16);
        let (initial, task) = store
            .subscribe_diff(role, vec![DiffScope::StaticRoutingInstances], tx)
            .await;
        drop(initial);
        subs.push(rx);
        tasks.push(task);
    }

    let b0 = LIVE.load(Relaxed);
    let t = Instant::now();
    let per_commit = puts_per_commit();
    let (mut first_put, mut put_transient) = (0, 0);
    let (mut commit_transient, mut diff_transient) = (0, 0);
    for c in 0..COMMITS {
        store
            .open_transaction("m", TransactionBase::Current)
            .await
            .unwrap();
        for k in 0..per_commit {
            let live = LIVE.load(Relaxed);
            PEAK.store(live, Relaxed);
            let n = INSTANCES * PER_INSTANCE + c * per_commit + k;
            let mut p = path(0);
            p.extend(["route".to_string(), prefix(n)]);
            // The edit alone: the snapshot reply is #774's.
            store
                .edit_transaction_path("m", &p, Some(&route_json(n)), None, None)
                .await
                .unwrap();
            let cost = PEAK.load(Relaxed) - live;
            // The first edit after open(Current) unshares running: one copy.
            if k == 0 {
                first_put = first_put.max(cost);
            } else {
                put_transient = put_transient.max(cost);
            }
        }
        // The store-level commit (the forwarders only run once this task
        // yields), then every subscriber's diff of it.
        let live = LIVE.load(Relaxed);
        PEAK.store(live, Relaxed);
        store.commit_transaction("m", None).await.unwrap();
        commit_transient = commit_transient.max(PEAK.load(Relaxed) - live);
        let live = LIVE.load(Relaxed);
        PEAK.store(live, Relaxed);
        drain(&mut subs).await;
        diff_transient = diff_transient.max(PEAK.load(Relaxed) - live);
    }
    let elapsed = t.elapsed();
    // Saturating: running cloned by `make_mut` has exact-capacity lists, so it
    // can be smaller than the deserialized seed it replaces.
    let after = LIVE.load(Relaxed).saturating_sub(b0);

    eprintln!(
        "one_config_live={one_config} json_len={json_len} commits={COMMITS} \
         puts={} in {elapsed:?} subscribers={} first_put_transient={first_put} ({:.2}x) \
         per_put_transient={put_transient} ({:.4}x) commit_transient={commit_transient} ({:.2}x) \
         diff_transient={diff_transient} ({:.1}x) live_after_commits_delta={after} ({:.2}x one config)",
        COMMITS * per_commit,
        SUBSCRIBERS.len(),
        first_put as f64 / one_config as f64,
        put_transient as f64 / one_config as f64,
        commit_transient as f64 / one_config as f64,
        diff_transient as f64 / one_config as f64,
        after as f64 / one_config as f64,
    );
    // Measured (#773): ~0. Running is the one config the transaction now
    // shares, `prev` and the `for_role` projections are gone, and tokio drops
    // a ring slot's value once every receiver read it (a lagging receiver
    // would keep `config` + diffs, without `prev` once the owed diffs exist).
    // The diff transient was ~75x at 66k while `diff_configs` walked both
    // configs as JSON per class; typed (#778) it is 1.3x for the three
    // classes together: 500 added routes' sections per class plus the two
    // 22k-route key indexes of the modified instance, per class.
    // A PUT is O(route) (#775): measured 1.7-2.9 KB (a route, its JSON, the
    // planned edit), so 8 KiB is headroom, not a config-sized bound. The
    // first PUT of a transaction unshares running (1.38x measured: one copy
    // plus the routes list growing past its exact clone capacity).
    // ponytail: bounds are the #776 debug-build measurements (live 0, commit
    // 0.14x, PUT 2986 B, first PUT 1.38x) and #778's (diff 1.3x) plus ~2x
    // headroom.
    assert!(
        after <= one_config / 8,
        "live after {COMMITS} commits {after} > 1/8 config ({one_config})"
    );
    assert!(
        commit_transient <= one_config / 4,
        "commit transient {commit_transient} > 1/4 config ({one_config})"
    );
    assert!(
        diff_transient <= one_config * 13 / 5,
        "diff transient {diff_transient} > 2.6x one config ({one_config})"
    );
    assert!(
        put_transient <= 8 * 1024,
        "per-PUT transient {put_transient} > 8 KiB"
    );
    assert!(
        first_put <= one_config * 3 / 2,
        "first PUT transient {first_put} > 1.5x one config ({one_config})"
    );
    for task in tasks {
        task.abort();
    }
}
