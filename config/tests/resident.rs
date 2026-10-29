//! Live-heap check for the config store (#766/#767/#773): a counting global
//! allocator reports what one route `PUT` and one commit cost at ~66k static
//! routes with live diff subscribers, and bounds what stays live after
//! several commits (the broadcast ring included).

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
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_sub(l.size(), Relaxed);
        let now = LIVE.fetch_add(new, Relaxed) + new;
        PEAK.fetch_max(now, Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static A: Counting = Counting;

const INSTANCES: u32 = 3;
const PER_INSTANCE: u32 = 22_000;
/// Commits measured after the seed, each carrying `PUTS_PER_COMMIT` single
/// route PUTs. ponytail: 4 x 60 PUTs (~175 ms each in a debug build, a PUT is
/// still O(config) until #775), raised back toward 2000 once it is O(route).
const COMMITS: u32 = 4;
const PUTS_PER_COMMIT: u32 = 60;
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
    let (mut put_transient, mut commit_transient, mut diff_transient) = (0, 0, 0);
    for c in 0..COMMITS {
        store
            .open_transaction("m", TransactionBase::Current)
            .await
            .unwrap();
        for k in 0..PUTS_PER_COMMIT {
            let live = LIVE.load(Relaxed);
            PEAK.store(live, Relaxed);
            let n = INSTANCES * PER_INSTANCE + c * PUTS_PER_COMMIT + k;
            let mut p = path(0);
            p.extend(["route".to_string(), prefix(n)]);
            store
                .set_transaction_path("m", &p, Some(&route_json(n)), None, None)
                .await
                .unwrap();
            put_transient = put_transient.max(PEAK.load(Relaxed) - live);
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
    let after = LIVE.load(Relaxed) - b0;

    eprintln!(
        "one_config_live={one_config} json_len={json_len} commits={COMMITS} \
         puts={} in {elapsed:?} subscribers={} per_put_transient={put_transient} \
         ({:.1}x) commit_transient={commit_transient} ({:.2}x) \
         diff_transient={diff_transient} ({:.1}x) live_after_commits_delta={after} ({:.2}x one config)",
        COMMITS * PUTS_PER_COMMIT,
        SUBSCRIBERS.len(),
        put_transient as f64 / one_config as f64,
        commit_transient as f64 / one_config as f64,
        diff_transient as f64 / one_config as f64,
        after as f64 / one_config as f64,
    );
    // Measured (#773): ~0. Running is the one config the transaction now
    // shares, `prev` and the `for_role` projections are gone, and tokio drops
    // a ring slot's value once every receiver read it (a lagging receiver
    // would keep `config` + diffs, without `prev` once the owed diffs exist).
    // The diff transient (~75x at 66k: `diff_configs` walks both configs as
    // JSON, per class) is printed, not bounded: the remaining commit cost.
    // ponytail: bounds from this PR's measurement plus headroom; #775/#776
    // tighten the per-PUT one.
    assert!(
        after <= one_config / 2,
        "live after {COMMITS} commits {after} > half a config ({one_config})"
    );
    assert!(
        commit_transient <= one_config,
        "commit transient {commit_transient} > one config ({one_config})"
    );
    assert!(
        put_transient <= 16 * one_config,
        "per-PUT transient {put_transient} > 16x one config ({one_config})"
    );
    for task in tasks {
        task.abort();
    }
}
