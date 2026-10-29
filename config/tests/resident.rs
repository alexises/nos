//! Live-heap check for the config store (#766/#767): a counting global
//! allocator reports what one route `PUT` and one commit cost at ~66k static
//! routes, and bounds what stays live after the commit.

#![allow(clippy::cast_precision_loss, reason = "printed ratios only")]
#![allow(
    unsafe_code,
    reason = "a GlobalAlloc impl is unsafe by definition; it only forwards to System"
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

use nos_config::ConfigStore;
use nos_proto::{Config, TransactionBase};

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
/// Extra single-route PUTs measured; the plan says 2000, lowered to 250 (~175 ms
/// each in a debug build, so 500 already took ~90 s) to stay near 60 s with the
/// base load (each PUT is O(config), itself a #766 finding).
const PUTS: u32 = 250;

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
    let copy = running.clone();
    let one_config = LIVE.load(Relaxed) - before_clone;
    drop(copy);
    let json_len = serde_json::to_vec(&running).unwrap().len();
    drop(running);

    let b0 = LIVE.load(Relaxed);
    store
        .open_transaction("m", TransactionBase::Current)
        .await
        .unwrap();
    let t = Instant::now();
    let mut put_transient = 0;
    for k in 0..PUTS {
        let live = LIVE.load(Relaxed);
        PEAK.store(live, Relaxed);
        let n = INSTANCES * PER_INSTANCE + k;
        let mut p = path(0);
        p.extend(["route".to_string(), prefix(n)]);
        store
            .set_transaction_path("m", &p, Some(&route_json(n)), None, None)
            .await
            .unwrap();
        put_transient = put_transient.max(PEAK.load(Relaxed) - live);
    }
    let puts_elapsed = t.elapsed();

    let live = LIVE.load(Relaxed);
    PEAK.store(live, Relaxed);
    store.commit_transaction("m", None).await.unwrap();
    let commit_peak = PEAK.load(Relaxed) - live;
    let after = LIVE.load(Relaxed) - b0;

    eprintln!(
        "one_config_live={one_config} json_len={json_len} puts={PUTS} in {puts_elapsed:?} \
         per_put_transient={put_transient} commit_transient={commit_peak} \
         commit_copies~{:.1} live_after_commit_delta={after} ({:.1}x one config)",
        commit_peak as f64 / one_config as f64,
        after as f64 / one_config as f64,
    );
    // ponytail: generous 6x bound, retuned in the fix PR once the copies are gone.
    // No subscriber here, so the broadcast ring's retained `CommitUpdate`s (and
    // their `diff_for` diffs, the bulk of dhat's t-end) are not counted: the fix
    // PR adds one.
    assert!(
        after <= 6 * one_config,
        "live after commit {after} > 6x one config ({one_config})"
    );
}
