//! `nos-e2e logd-mem`: the `nos-logd` memory-profiling load (#757), and the
//! `logd-memory` phase (#756) that asserts on the same load. `logd-mem` is not
//! a phase (it asserts nothing, not in `phases::ALL`): it drives sequential
//! per-route `PUT`s into one uncommitted transaction on router-a, or on
//! router-b with `LOGD_MEM_ROUTER=b` (every request is one `rest request` log
//! line, the churn that matters), optionally with a concurrent
//! `GET /v1/logs?limit=20000` poll loop, and prints every `nos-*` daemon's
//! `VmRSS`/`VmHWM` and the container cgroup's `memory.current`/`memory.max`
//! along the way plus, after SIGINT-ing `nos-logd`, the dhat `t-gmax`/`t-end`
//! totals. Knobs (env): `LOGD_MEM_ROUTES` (default 20000), `LOGD_MEM_POLL=1`,
//! `LOGD_MEM_IDLE` (seconds, default 60). The dhat totals need a `nos-logd`
//! built with `nos-log/dhat-heap` that writes `/tmp/dhat-logd.json` (see
//! `docs/architecture/logging.md`).

use std::time::Duration;

use anyhow::{bail, ensure};
use reqwest::Method;

use crate::router::{log, Router};
use crate::world::World;

const TX: &str = "logdmem";
const DHAT: &str = "/tmp/dhat-logd.json";

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Every `nos-*` process (`comm pid VmRSS VmHWM`) plus the container cgroup.
const SAMPLE_SCRIPT: &str = "for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); case $c in nos-*) echo \"$c ${p#/proc/} $(grep -E '^(VmRSS|VmHWM)' $p/status | tr -s ' \\n' ' ')\";; esac; done; echo \"cgroup current=$(cat /sys/fs/cgroup/memory.current) max=$(cat /sys/fs/cgroup/memory.max)\"";

/// Picks the pid by `comm`.
const FIND_PID: &str = "for p in /proc/[0-9]*; do case $(cat $p/comm 2>/dev/null) in nos-logd*) echo ${p#/proc/}; break;; esac; done";

/// Logs a per-daemon sample; returns `nos-logd`'s `VmRSS` in kB.
async fn sample(w: &World, router: &Router, label: &str) -> anyhow::Result<u64> {
    let (_, out) = w
        .dock
        .exec_root(router.name(), &["sh", "-c", SAMPLE_SCRIPT])
        .await?;
    let mut logd = 0;
    for line in out.lines() {
        log(format!("SAMPLE {label} {line}"));
        if line.starts_with("nos-logd ")
            && let Some(rest) = line.split("VmRSS:").nth(1)
        {
            logd = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(0);
        }
    }
    Ok(logd)
}

/// Opens an uncommitted transaction and PUTs `routes` routes one by one,
/// sampling every 2000; returns `(puts, nos-logd RSS kB)` per sample.
async fn put_load(
    w: &World,
    a: &Router,
    routes: u64,
    poll: bool,
) -> anyhow::Result<Vec<(u64, u64)>> {
    let tx = format!("/v1/transactions/{TX}");
    let _ = a.rest(Method::DELETE, &tx, None).await?;
    a.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
        .await?;
    let sri = format!("{tx}/static-routing-instance/s1");
    let (st, body) = a
        .rest(Method::PUT, &sri, Some(r#"{"name":"s1","routes":[]}"#))
        .await?;
    if !(200..300).contains(&st) {
        bail!("PUT {sri} -> {st}: {body}");
    }

    let mut samples = Vec::new();
    let load = async {
        for i in 0..routes {
            let prefix = format!("10.{}.{}.0/24", (i >> 8) & 255, i & 255);
            let body = format!(r#"{{"subnet":"{prefix}","gateway":"192.0.2.1"}}"#);
            let path = format!("{sri}/route/{}", prefix.replace('/', "%2F"));
            let (st, text) = a.rest(Method::PUT, &path, Some(&body)).await?;
            if !(200..300).contains(&st) {
                bail!("PUT {path} -> {st}: {text}");
            }
            if (i + 1) % 2000 == 0 {
                let rss = sample(w, a, &format!("puts={}", i + 1)).await?;
                samples.push((i + 1, rss));
            }
        }
        anyhow::Ok(())
    };
    let poller = async {
        let mut n = 0u64;
        loop {
            let _ = a.rest(Method::GET, "/v1/logs?limit=20000", None).await;
            n += 1;
            if n.is_multiple_of(20) {
                log(format!("poll count {n}"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    if poll {
        tokio::select! {
            r = load => r?,
            () = poller => {}
        }
    } else {
        load.await?;
    }
    Ok(samples)
}

pub async fn run(w: &World) -> anyhow::Result<()> {
    let a = match std::env::var("LOGD_MEM_ROUTER").as_deref() {
        Ok("b") => w.b()?,
        _ => w.a()?,
    };
    let routes = env("LOGD_MEM_ROUTES", 20_000);
    let poll = env("LOGD_MEM_POLL", 0) == 1;
    let idle = env("LOGD_MEM_IDLE", 60);

    let script = format!("cat /proc/$({FIND_PID})/cmdline | tr '\\0' ' '");
    let (_, cmd) = w.dock.exec_root(a.name(), &["sh", "-c", &script]).await?;
    log(format!("nos-logd cmdline: {}", cmd.trim()));
    sample(w, a, "baseline").await?;

    put_load(w, a, routes, poll).await?;
    sample(w, a, "after-load").await?;
    let _ = a
        .rest(Method::DELETE, &format!("/v1/transactions/{TX}"), None)
        .await?;
    tokio::time::sleep(Duration::from_secs(idle)).await;
    sample(w, a, &format!("idle+{idle}s")).await?;

    // SIGINT = the watchdog's own stop signal: dhat writes its report on exit.
    let kill = format!("kill -INT $({FIND_PID})");
    w.dock.exec_root(a.name(), &["sh", "-c", &kill]).await?;
    tokio::time::sleep(Duration::from_secs(8)).await;
    let (_, json) = w.dock.exec_root(a.name(), &["cat", DHAT]).await?;
    let v: serde_json::Value = serde_json::from_str(json.trim())?;
    let sum = |key: &str| -> u64 {
        v["pps"]
            .as_array()
            .map_or(0, |p| p.iter().filter_map(|e| e[key].as_u64()).sum())
    };
    log(format!(
        "DHAT t-gmax={} t-end={} (bytes; pps={})",
        sum("gb"),
        sum("eb"),
        v["pps"].as_array().map_or(0, Vec::len)
    ));
    Ok(())
}

/// The `logd-memory` phase (#756): `nos-logd`'s RSS stays flat under request
/// churn, does not grow at idle, and the watchdog delivered `MALLOC_ARENA_MAX=1`.
pub async fn phase(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    // /proc/<pid>/environ of another uid is unreadable even for the container's
    // root (no CAP_SYS_PTRACE), so check the watchdog's own `starting` line.
    a.wait("starting process=nos-logd program=.* env=MALLOC_ARENA_MAX=1")
        .await?;

    let samples = put_load(w, a, 20_000, false).await?;
    let at = |n: u64| samples.iter().find(|s| s.0 == n).map(|s| s.1);
    let (Some(r10), Some(r20)) = (at(10_000), at(20_000)) else {
        bail!("no RSS sample at 10000/20000 PUTs: {samples:?}");
    };
    let end = sample(w, a, "after-load").await?;
    let _ = a
        .rest(Method::DELETE, &format!("/v1/transactions/{TX}"), None)
        .await?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let idle = sample(w, a, "idle+30s").await?;

    // Flat: at most +50% or +50 MB (whichever is larger) from 10k to 20k PUTs.
    let allowed = r10 + (r10 / 2).max(50 * 1024);
    log(format!(
        "logd-memory: rss@10k={r10} kB rss@20k={r20} kB limit={allowed} kB end={end} kB idle={idle} kB"
    ));
    ensure!(
        r20 <= allowed,
        "nos-logd RSS grew {r10} -> {r20} kB (limit {allowed})"
    );
    // 1 MiB of slack: the idle path itself allocates a little (rest request logs).
    ensure!(
        idle <= end + 1024,
        "nos-logd RSS grew at idle: {end} -> {idle} kB"
    );
    Ok(())
}
