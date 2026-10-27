//! `nos-e2e logd-mem`: the `nos-logd` memory-profiling load (#757). Not a
//! phase (it asserts nothing and is not in `phases::ALL`): it drives
//! sequential per-route `PUT`s into one uncommitted transaction on router-a
//! (every request is one `rest request` log line, the churn that matters),
//! optionally with a concurrent `GET /v1/logs?limit=20000` poll loop, and
//! prints `nos-logd`'s `VmRSS`/`VmHWM`/smaps_rollup along the way plus, after
//! SIGINT-ing it, the dhat `t-gmax`/`t-end` totals. Knobs (env):
//! `LOGD_MEM_ROUTES` (default 20000), `LOGD_MEM_POLL=1`, `LOGD_MEM_IDLE`
//! (seconds, default 60). Needs a `nos-logd` built with `nos-log/dhat-heap`
//! that writes `/tmp/dhat-logd.json` (see `docs/architecture/logging.md`).

use std::time::Duration;

use anyhow::bail;
use reqwest::Method;

use crate::router::log;
use crate::world::World;

const TX: &str = "logdmem";
const DHAT: &str = "/tmp/dhat-logd.json";

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Picks the pid by `comm` (the binary or the lab's `nos-logd.real`).
const FIND_PID: &str = "for p in /proc/[0-9]*; do case $(cat $p/comm 2>/dev/null) in nos-logd*) echo ${p#/proc/}; break;; esac; done";

async fn sample(w: &World, label: &str) -> anyhow::Result<()> {
    let script = format!(
        "p=$({FIND_PID}); echo \"{label} pid=$p $(grep -E '^(VmRSS|VmHWM)' /proc/$p/status | tr -s ' \\n' ' ')\""
    );
    let (_, out) = w.dock.exec_root("router-a", &["sh", "-c", &script]).await?;
    log(format!("SAMPLE {}", out.trim()));
    Ok(())
}

pub async fn run(w: &World) -> anyhow::Result<()> {
    let a = w.a()?;
    let routes = env("LOGD_MEM_ROUTES", 20_000);
    let poll = env("LOGD_MEM_POLL", 0) == 1;
    let idle = env("LOGD_MEM_IDLE", 60);

    let script = format!("cat /proc/$({FIND_PID})/cmdline | tr '\\0' ' '");
    let (_, cmd) = w.dock.exec_root("router-a", &["sh", "-c", &script]).await?;
    log(format!("nos-logd cmdline: {}", cmd.trim()));
    sample(w, "baseline").await?;

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
                sample(w, &format!("puts={}", i + 1)).await?;
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

    sample(w, "after-load").await?;
    let _ = a.rest(Method::DELETE, &tx, None).await?;
    tokio::time::sleep(Duration::from_secs(idle)).await;
    sample(w, &format!("idle+{idle}s")).await?;

    // SIGINT = the watchdog's own stop signal: dhat writes its report on exit.
    let kill = format!("kill -INT $({FIND_PID})");
    w.dock.exec_root("router-a", &["sh", "-c", &kill]).await?;
    tokio::time::sleep(Duration::from_secs(8)).await;
    let (_, json) = w.dock.exec_root("router-a", &["cat", DHAT]).await?;
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
