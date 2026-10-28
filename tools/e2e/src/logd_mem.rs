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

use std::collections::HashMap;
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

/// Picks the pid by `comm` prefix.
fn find_pid(comm: &str) -> String {
    format!("for p in /proc/[0-9]*; do case $(cat $p/comm 2>/dev/null) in {comm}*) echo ${{p#/proc/}}; break;; esac; done")
}

/// `comm -> (pid, VmRSS kB, VmHWM kB)` for every `nos-*` process; logs every
/// line (and the cgroup's) as `SAMPLE <label> ...`.
pub(crate) async fn sample_all(
    w: &World,
    router: &Router,
    label: &str,
) -> anyhow::Result<HashMap<String, (u64, u64, u64)>> {
    let (_, out) = w
        .dock
        .exec_root(router.name(), &["sh", "-c", SAMPLE_SCRIPT])
        .await?;
    let mut map = HashMap::new();
    for line in out.lines() {
        log(format!("SAMPLE {label} {line}"));
        if let Some((comm, v)) = parse_sample_line(line) {
            map.insert(comm, v);
        }
    }
    Ok(map)
}

/// `nos-x 123 VmRSS: 10 kB VmHWM: 20 kB` -> `("nos-x", (123, 10, 20))`.
fn parse_sample_line(line: &str) -> Option<(String, (u64, u64, u64))> {
    let t: Vec<&str> = line.split_whitespace().collect();
    if t.len() < 7 || !t[0].starts_with("nos-") || t[2] != "VmRSS:" || t[5] != "VmHWM:" {
        return None;
    }
    Some((
        t[0].to_string(),
        (t[1].parse().ok()?, t[3].parse().ok()?, t[6].parse().ok()?),
    ))
}

/// Logs a per-daemon sample; returns `nos-logd`'s `VmRSS` in kB.
pub(crate) async fn sample(w: &World, router: &Router, label: &str) -> anyhow::Result<u64> {
    Ok(sample_all(w, router, label)
        .await?
        .get("nos-logd")
        .map_or(0, |v| v.1))
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

    let script = format!(
        "cat /proc/$({})/cmdline | tr '\\0' ' '",
        find_pid("nos-logd")
    );
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
    let kill = format!("kill -INT $({})", find_pid("nos-logd"));
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

/// Static routes one list may hold (the 2 MiB request body limit, see the
/// `PUT /v1/transactions/{tx}` docs).
const MAX_ROUTES_PER_INSTANCE: u64 = 25_000;
const WAVE_TX: &str = "wavemem";

/// `nos-e2e mem-wave` (#767): `WAVE_COUNT` cumulative commits of `WAVE_ROUTES`
/// static routes each (per-route `PUT`s, as REST clients do), sampling every
/// daemon after each commit and `WAVE_IDLE` seconds later, then the dhat
/// totals of `nos-configd` and `nos-restd` (images built with
/// `nos-config/dhat-heap nos-rest/dhat-heap`, see `docs/architecture/config-protocol.md`).
/// Router from `LOGD_MEM_ROUTER` (`b` for the #766 report). Not a phase.
#[allow(
    clippy::many_single_char_names,
    reason = "short loop locals in a load script"
)]
pub async fn wave(w: &World) -> anyhow::Result<()> {
    let r = match std::env::var("LOGD_MEM_ROUTER").as_deref() {
        Ok("b") => w.b()?,
        _ => w.a()?,
    };
    let (waves, per_wave, idle) = (
        env("WAVE_COUNT", 12),
        env("WAVE_ROUTES", 5500),
        env("WAVE_IDLE", 0),
    );
    let instances = (waves * per_wave).div_ceil(MAX_ROUTES_PER_INSTANCE).max(1);
    let mut pids: Option<(u64, u64)> = None;
    check_pids(&sample_all(w, r, "baseline").await?, &mut pids)?;

    let tx = format!("/v1/transactions/{WAVE_TX}");
    let _ = r.rest(Method::DELETE, &tx, None).await?;
    for wave in 0..waves {
        r.rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
            .await?;
        if wave == 0 {
            for k in 0..instances {
                let body = format!(r#"{{"name":"sw{k}","routes":[]}}"#);
                put(r, &format!("{tx}/static-routing-instance/sw{k}"), &body).await?;
            }
        }
        for i in 0..per_wave {
            let n = wave * per_wave + i;
            let a = 0x6440_0000_u64 + n; // 100.64.0.0 + n
            let prefix = format!(
                "{}.{}.{}.{}/32",
                a >> 24,
                (a >> 16) & 255,
                (a >> 8) & 255,
                a & 255
            );
            let body = format!(r#"{{"subnet":"{prefix}","gateway":"192.0.2.1"}}"#);
            let path = format!(
                "{tx}/static-routing-instance/sw{}/route/{}",
                n % instances,
                prefix.replace('/', "%2F")
            );
            put(r, &path, &body).await?;
            if (i + 1) % 2000 == 0 {
                let s = sample_all(w, r, &format!("wave{wave}-puts={}", i + 1)).await?;
                check_pids(&s, &mut pids)?;
            }
        }
        r.rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
            .await?;
        let s = sample_all(w, r, &format!("wave{wave}-committed")).await?;
        check_pids(&s, &mut pids)?;
        tokio::time::sleep(Duration::from_secs(idle)).await;
        let s = sample_all(w, r, &format!("wave{wave}-idle")).await?;
        check_pids(&s, &mut pids)?;
    }

    let (st, cfg) = r.rest(Method::GET, "/v1/config", None).await?;
    log(format!(
        "running config JSON bytes={} (status {st})",
        cfg.len()
    ));
    // SIGINT = the watchdog's own stop signal: dhat writes its report on exit.
    for comm in ["nos-configd", "nos-restd"] {
        let kill = format!("kill -INT $({})", find_pid(comm));
        w.dock.exec_root(r.name(), &["sh", "-c", &kill]).await?;
    }
    tokio::time::sleep(Duration::from_secs(15)).await;
    for (daemon, file) in [
        ("nos-configd", "/tmp/dhat-configd.json"),
        ("nos-restd", "/tmp/dhat-restd-rt1.json"),
    ] {
        let (_, json) = w.dock.exec_root(r.name(), &["cat", file]).await?;
        let v: serde_json::Value = serde_json::from_str(json.trim())?;
        log(format!(
            "DHAT {daemon} t-gmax={} t-end={}",
            dhat_sum(&v, "gb"),
            dhat_sum(&v, "eb")
        ));
        for line in dhat_top(&v, 8) {
            log(format!("DHAT {daemon} {line}"));
        }
    }
    Ok(())
}

async fn put(r: &Router, path: &str, body: &str) -> anyhow::Result<()> {
    let (st, text) = r.rest(Method::PUT, path, Some(body)).await?;
    ensure!((200..300).contains(&st), "PUT {path} -> {st}: {text}");
    Ok(())
}

/// Fails if `nos-configd` or `nos-restd` changed pid (restarted/OOM-killed).
fn check_pids(
    s: &HashMap<String, (u64, u64, u64)>,
    seen: &mut Option<(u64, u64)>,
) -> anyhow::Result<()> {
    let cur = (
        s.get("nos-configd").map_or(0, |v| v.0),
        s.get("nos-restd").map_or(0, |v| v.0),
    );
    ensure!(
        cur.0 != 0 && cur.1 != 0,
        "nos-configd/nos-restd not running: {s:?}"
    );
    ensure!(
        seen.is_none_or(|p| p == cur),
        "daemon restarted: pids {seen:?} -> {cur:?}"
    );
    *seen = Some(cur);
    Ok(())
}

fn dhat_sum(v: &serde_json::Value, key: &str) -> u64 {
    v["pps"]
        .as_array()
        .map_or(0, |p| p.iter().filter_map(|e| e[key].as_u64()).sum())
}

/// The top `n` dhat program points by max bytes (`mb`) and by total bytes
/// (`tb`), one line each with the first 3 frames resolved from `ftbl`.
fn dhat_top(v: &serde_json::Value, n: usize) -> Vec<String> {
    let empty = Vec::new();
    let pps = v["pps"].as_array().unwrap_or(&empty);
    let ftbl = v["ftbl"].as_array().unwrap_or(&empty);
    let mut out = Vec::new();
    for (key, name) in [("mb", "max"), ("tb", "total")] {
        let mut order: Vec<&serde_json::Value> = pps.iter().collect();
        order.sort_by_key(|e| std::cmp::Reverse(e[key].as_u64().unwrap_or(0)));
        for e in order.into_iter().take(n) {
            let frames: Vec<String> = e["fs"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .take(3)
                .map(|i| {
                    i.as_u64()
                        .and_then(|i| ftbl.get(usize::try_from(i).ok()?))
                        .and_then(|f| f.as_str())
                        .unwrap_or("?")
                        .to_string()
                })
                .collect();
            out.push(format!(
                "top-{name} {key}={} gb={} eb={} :: {}",
                e[key],
                e["gb"],
                e["eb"],
                frames.join(" <- ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_sample_line() {
        assert_eq!(
            parse_sample_line("nos-configd 42 VmRSS: 1000 kB VmHWM: 2000 kB"),
            Some(("nos-configd".to_string(), (42, 1000, 2000)))
        );
        assert_eq!(parse_sample_line("cgroup current=1 max=2"), None);
    }

    #[test]
    fn dhat_top_resolves_frames_and_orders() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"pps":[{"tb":10,"mb":1,"gb":1,"eb":0,"fs":[0,1]},{"tb":5,"mb":9,"gb":9,"eb":2,"fs":[2,0,1,0]}],
                "ftbl":["a","b","c"]}"#,
        )
        .unwrap();
        let top = dhat_top(&v, 1);
        assert_eq!(top.len(), 2);
        assert!(top[0].starts_with("top-max mb=9") && top[0].ends_with("c <- a <- b"));
        assert!(top[1].starts_with("top-total tb=10") && top[1].ends_with("a <- b"));
        assert_eq!(dhat_sum(&v, "gb"), 10);
    }
}
