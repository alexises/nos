//! `nos-e2e logd-mem`: the `nos-logd` memory-profiling load (#757), and the
//! `logd-memory` phase (#756) that asserts on the same load; likewise
//! `mem-wave` (#767) and its `config-mem` phase (#776). `logd-mem` is not
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
use std::time::{Duration, Instant};

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
const SAMPLE_SCRIPT: &str = "for p in /proc/[0-9]*; do c=$(cat $p/comm 2>/dev/null); case $c in nos-*) echo \"$c ${p#/proc/} $(grep -E '^(VmRSS|VmHWM)' $p/status | tr -s ' \\n' ' ')\";; esac; done; echo \"cgroup current=$(cat /sys/fs/cgroup/memory.current) max=$(cat /sys/fs/cgroup/memory.max) peak=$(cat /sys/fs/cgroup/memory.peak 2>/dev/null)\"";

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

/// `nos-x 123 VmHWM: 20 kB VmRSS: 10 kB` (either order) -> `("nos-x", (123, 10, 20))`;
/// `cgroup current=2048 max=max` -> `("cgroup", (0, 2, 0))` (bytes -> kB, `max` = 0).
fn parse_sample_line(line: &str) -> Option<(String, (u64, u64, u64))> {
    if let Some(rest) = line.strip_prefix("cgroup ") {
        let kb = |key: &str| -> u64 {
            rest.split_whitespace()
                .find_map(|kv| kv.strip_prefix(key)?.parse::<u64>().ok())
                .map_or(0, |b| b / 1024)
        };
        return Some(("cgroup".to_string(), (0, kb("current="), kb("max="))));
    }
    let t: Vec<&str> = line.split_whitespace().collect();
    if !t.first()?.starts_with("nos-") {
        return None;
    }
    let after = |key: &str| -> Option<u64> {
        t.iter()
            .position(|x| *x == key)
            .and_then(|i| t.get(i + 1))?
            .parse()
            .ok()
    };
    Some((
        t[0].to_string(),
        (t.get(1)?.parse().ok()?, after("VmRSS:")?, after("VmHWM:")?),
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
/// `nos-configd`'s per-commit dhat `HeapStats` line (dhat image only, #796).
const HEAP_LINE: &str = "heap after commit";
/// `nos-restd`'s SIGUSR1 dhat `HeapStats` line (dhat image only, #798).
const RESTD_HEAP_LINE: &str = "restd heap stats";
/// One `sample_all` result under its label.
type Labelled = (String, HashMap<String, (u64, u64, u64)>);

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
    wave_load(w, r).await?;

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
        let Ok(v) = serde_json::from_str::<serde_json::Value>(json.trim()) else {
            log(format!(
                "DHAT {daemon}: no report at {file} (not a dhat-heap image?)"
            ));
            continue;
        };
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

/// The `config-mem` phase (#776): the `mem-wave` load on router-b, asserting
/// nos-configd's `VmRSS` after each commit from wave 2 on stays within ±25% of
/// the wave-2 value, the cgroup's sampled `memory.current` stays under 1.5 GiB,
/// and the watchdog started nos-configd with `MALLOC_ARENA_MAX=1`. `VmHWM` and
/// the idle samples are logged, not asserted (plan Q5).
pub async fn config_phase(w: &World) -> anyhow::Result<()> {
    let b = w.b()?;
    b.wait("starting process=nos-configd program=.* env=MALLOC_ARENA_MAX=1")
        .await?;
    let samples = wave_load(w, b).await?;

    let cgroup_peak = samples
        .iter()
        .filter_map(|(_, s)| s.get("cgroup"))
        .map(|c| c.1)
        .max()
        .unwrap_or(0);
    let committed: Vec<u64> = samples
        .iter()
        .filter(|(l, _)| l.ends_with("-committed"))
        .map(|(_, s)| s.get("nos-configd").map_or(0, |v| v.1))
        .collect();
    let (base, configd_verdict) = rss_flat("nos-configd", &committed, 0)?;
    log(format!(
        "config-mem: configd VmRSS after commit (kB) {committed:?} wave2={base} cgroup peak={cgroup_peak} kB"
    ));
    let restd: Vec<u64> = samples
        .iter()
        .filter(|(l, _)| l.ends_with("-committed"))
        .map(|(_, s)| s.get("nos-restd").map_or(0, |v| v.1))
        .collect();
    let (base, restd_verdict) = rss_flat("nos-restd", &restd, RESTD_SLACK_KB)?;
    log(format!(
        "config-mem: restd VmRSS after commit (kB) {restd:?} wave2={base}"
    ));
    // Both verdicts are logged before either fails, so one daemon's miss never hides the other's.
    for v in [&configd_verdict, &restd_verdict] {
        if let Err(e) = v {
            log(format!("config-mem: {e}"));
        }
    }
    configd_verdict?;
    restd_verdict?;
    ensure!(
        cgroup_peak < 1536 * 1024,
        "cgroup memory.current peaked at {cgroup_peak} kB (limit 1.5 GiB)"
    );
    Ok(())
}

/// `nos-restd`'s absolute upper slack (kB): ~42 MB at wave 2, so ±25% alone
/// is inside run-to-run noise (#801, owner decision).
const RESTD_SLACK_KB: u64 = 15_360;

/// Checks every after-commit `VmRSS` of `name` from wave 2 on is within ±25% of
/// the baseline, the upper bound widened to `base + slack_kb` if that is larger.
/// The baseline is the median of waves 2-4 (one sample can sit on a peak or a
/// trough of an allocator's purge cycle, #801); returns it and the verdict.
fn rss_flat(
    name: &str,
    committed: &[u64],
    slack_kb: u64,
) -> anyhow::Result<(u64, anyhow::Result<()>)> {
    if committed.len() < 5 {
        bail!("config-mem needs at least 5 waves, got {committed:?}");
    }
    let mut early = committed[2..5].to_vec();
    early.sort_unstable();
    let base = early[1];
    let (lo, hi) = (base - base / 4, base + (base / 4).max(slack_kb));
    let verdict = match committed[2..]
        .iter()
        .enumerate()
        .find(|(_, r)| !(lo..=hi).contains(*r))
    {
        Some((i, r)) => Err(anyhow::anyhow!(
            "{name} VmRSS {r} kB after wave {} is outside the band of the waves 2-4 median {base} kB (±25%, +{slack_kb} kB slack)",
            i + 2
        )),
        None => Ok(()),
    };
    Ok((base, verdict))
}

/// The `mem-wave` load: `WAVE_COUNT` (12) cumulative commits of `WAVE_ROUTES`
/// (5500) per-route `PUT`s on `r`, sampling every 2000 `PUT`s, after each
/// commit (`wave<n>-committed`) and `WAVE_IDLE` (0) seconds later
/// (`wave<n>-idle`). Fails if nos-configd or nos-restd changed pid.
async fn wave_load(w: &World, r: &Router) -> anyhow::Result<Vec<Labelled>> {
    let (waves, per_wave, idle) = (
        env("WAVE_COUNT", 12),
        env("WAVE_ROUTES", 5500),
        env("WAVE_IDLE", 0),
    );
    let instances = (waves * per_wave).div_ceil(MAX_ROUTES_PER_INSTANCE).max(1);
    // Only a dhat `nos-restd` takes `--profile-memory-out` and handles
    // SIGUSR1; a default build would die of it (#798).
    let script = format!(
        "cat /proc/$({})/cmdline | tr '\\0' ' '",
        find_pid("nos-restd")
    );
    let (_, cmd) = w.dock.exec_root(r.name(), &["sh", "-c", &script]).await?;
    let mut smp = Sampler {
        w,
        r,
        dhat: cmd.contains("--profile-memory-out"),
        pids: None,
        out: Vec::new(),
    };
    smp.take("baseline".into()).await?;

    let tx = format!("/v1/transactions/{WAVE_TX}");
    let _ = r.rest(Method::DELETE, &tx, None).await?;
    for wave in 0..waves {
        let started = Instant::now();
        let body = r
            .rest_expect(Method::POST, &format!("{tx}?base=current"), None, 201)
            .await?;
        log(format!(
            "OPEN wave{wave} {} ms {} bytes",
            started.elapsed().as_millis(),
            body.len()
        ));
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
                let label = format!("wave{wave}-puts={}", i + 1);
                smp.take(label).await?;
            }
        }
        let heaps = r.count(HEAP_LINE);
        let started = Instant::now();
        let body = r
            .rest_expect(Method::POST, &format!("{tx}/commit"), None, 200)
            .await?;
        log(format!(
            "COMMIT wave{wave} {} ms {} bytes",
            started.elapsed().as_millis(),
            body.len()
        ));
        smp.take(format!("wave{wave}-committed")).await?;
        // Dhat image only (#796): configd's live heap at this commit, next to
        // the RSS sample above. Wave 0 waits once to learn whether it logs one.
        if (wave == 0 || heaps > 0)
            && r.logs
                .wait_over(HEAP_LINE, heaps, Duration::from_secs(5))
                .await
        {
            let line = r.logs.last(HEAP_LINE).unwrap_or_default();
            let rss = smp
                .out
                .last()
                .and_then(|(_, s)| s.get("nos-configd"))
                .map_or(0, |v| v.1);
            log(format!("HEAP wave{wave} configd VmRSS={rss} kB {line}"));
        }
        tokio::time::sleep(Duration::from_secs(idle)).await;
        smp.take(format!("wave{wave}-idle")).await?;
    }
    Ok(smp.out)
}

/// `wave_load`'s sampling state.
struct Sampler<'a> {
    w: &'a World,
    r: &'a Router,
    /// `nos-restd` is a dhat build: SIGUSR1 it at every sample.
    dhat: bool,
    pids: Option<(u64, u64)>,
    out: Vec<Labelled>,
}

impl Sampler<'_> {
    /// One `sample_all` under `label`, pid-checked, appended to `out`; on a
    /// dhat image also `nos-restd`'s live heap next to its `VmRSS` (#798).
    async fn take(&mut self, label: String) -> anyhow::Result<()> {
        let s = sample_all(self.w, self.r, &label).await?;
        check_pids(&s, &mut self.pids)?;
        if self.dhat {
            let (pid, rss, _) = s.get("nos-restd").copied().unwrap_or_default();
            let before = self.r.count(RESTD_HEAP_LINE);
            let kill = format!("kill -USR1 {pid}");
            self.w
                .dock
                .exec_root(self.r.name(), &["sh", "-c", &kill])
                .await?;
            if self
                .r
                .logs
                .wait_over(RESTD_HEAP_LINE, before, Duration::from_secs(5))
                .await
            {
                let line = self.r.logs.last(RESTD_HEAP_LINE).unwrap_or_default();
                log(format!("HEAP {label} restd VmRSS={rss} kB {line}"));
            }
        }
        self.out.push((label, s));
        Ok(())
    }
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

/// The top `n` dhat program points by max bytes (`mb`), total bytes (`tb`)
/// and bytes still live at exit (`eb`), one line each: the first 2 frames
/// below the allocator plus the first 3 NOS frames (`nos_*`), resolved from
/// `ftbl` with the address prefix and `(???:0:0)` suffix stripped.
fn dhat_top(v: &serde_json::Value, n: usize) -> Vec<String> {
    let empty = Vec::new();
    let pps = v["pps"].as_array().unwrap_or(&empty);
    let ftbl = v["ftbl"].as_array().unwrap_or(&empty);
    let mut out = Vec::new();
    for (key, name) in [("mb", "max"), ("tb", "total"), ("eb", "end")] {
        let mut order: Vec<&serde_json::Value> = pps.iter().collect();
        order.sort_by_key(|e| std::cmp::Reverse(e[key].as_u64().unwrap_or(0)));
        for e in order.into_iter().take(n) {
            let all: Vec<&str> = e["fs"]
                .as_array()
                .unwrap_or(&empty)
                .iter()
                .map(|i| {
                    i.as_u64()
                        .and_then(|i| ftbl.get(usize::try_from(i).ok()?))
                        .and_then(|f| f.as_str())
                        .map_or("?", frame_name)
                })
                .filter(|f| !f.contains("dhat::Alloc"))
                .collect();
            let nos = all.iter().skip(2).filter(|f| f.contains("nos_")).take(3);
            let frames: Vec<&str> = all.iter().take(2).chain(nos).copied().collect();
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

/// `0x55..: <a as b>::f (???:0:0)` -> `<a as b>::f`.
fn frame_name(f: &str) -> &str {
    let f = f.split_once(": ").map_or(f, |(_, rest)| rest);
    f.strip_suffix(" (???:0:0)").unwrap_or(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_sample_line() {
        assert_eq!(
            parse_sample_line("nos-configd 42 VmHWM:\t 2000 kB VmRSS:\t 1000 kB "),
            Some(("nos-configd".to_string(), (42, 1000, 2000)))
        );
        assert_eq!(
            parse_sample_line("cgroup current=4096 max=max peak=8192"),
            Some(("cgroup".to_string(), (0, 4, 0)))
        );
        assert_eq!(parse_sample_line("other 1 2"), None);
    }

    #[test]
    fn rss_flat_is_twenty_five_percent_of_the_waves_two_to_four_median() {
        let ok = |c: &[u64]| rss_flat("d", c, 0).map(|(_, v)| v.is_ok());
        assert!(ok(&[1, 2, 3, 4]).is_err(), "fewer than 5 waves");
        // Median of waves 2-4: 400, 300 and 500 -> 400.
        assert_eq!(rss_flat("d", &[9, 9, 400, 300, 500], 0).unwrap().0, 400);
        assert!(ok(&[9, 9, 400, 300, 500]).unwrap());
        assert!(ok(&[9, 9, 400, 400, 400, 500]).unwrap());
        assert!(!ok(&[9, 9, 400, 400, 400, 501]).unwrap());
        assert!(!ok(&[9, 9, 400, 400, 400, 299]).unwrap());
        // A peak at wave 2 does not set the baseline.
        assert_eq!(rss_flat("d", &[9, 9, 900, 400, 400], 0).unwrap().0, 400);
        // Slack: base 40000 -> +25% = 50000 fails, +15360 = 55360 passes.
        let flat = [9, 9, 40_000, 40_000, 40_000];
        let with = |last: u64, slack: u64| {
            let mut c = flat.to_vec();
            c.push(last);
            rss_flat("d", &c, slack).unwrap().1.is_ok()
        };
        assert!(with(55_000, 15_360));
        assert!(!with(55_000, 0));
        assert!(!with(55_361, 15_360), "fails both bands");
        assert!(!with(29_999, 15_360), "slack is upper-only");
    }

    #[test]
    fn dhat_top_resolves_frames_and_orders() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{"pps":[{"tb":10,"mb":1,"gb":1,"eb":0,"fs":[0,1]},{"tb":5,"mb":9,"gb":9,"eb":2,"fs":[3,2,0,4,1,4]}],
                "ftbl":["a","nos_x","c","0x1: dhat::Alloc (???:0:0)","std"]}"#,
        )
        .unwrap();
        let top = dhat_top(&v, 1);
        assert_eq!(top.len(), 3);
        assert!(top[0].starts_with("top-max mb=9") && top[0].ends_with("c <- a <- nos_x"));
        assert!(top[1].starts_with("top-total tb=10") && top[1].ends_with("a <- nos_x"));
        assert!(top[2].starts_with("top-end eb=2"));
        assert_eq!(frame_name("0x5: <a as b>::f (???:0:0)"), "<a as b>::f");
        assert_eq!(dhat_sum(&v, "gb"), 10);
    }
}
