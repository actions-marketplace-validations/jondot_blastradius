//! Progress for long scans: a line on stderr every 2 s when stderr is a terminal, every 10 s when it is not, and
//! none with `--quiet`. The walker calls `tick` for every file; `tick` costs a counter bump until the interval is up.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How often a line is due, and when the last one went out.
#[derive(Debug, Clone)]
pub struct Pacer {
    pub every: Duration,
    last: Duration,
}

impl Pacer {
    pub fn new(every: Duration) -> Pacer {
        Pacer { every, last: Duration::ZERO }
    }

    /// Is a line due at `elapsed` since the start? Asking marks it as printed.
    pub fn due(&mut self, elapsed: Duration) -> bool {
        if elapsed >= self.last + self.every {
            self.last = elapsed;
            true
        } else {
            false
        }
    }
}

/// The interval for a stream: 2 s on a terminal, 10 s when output goes to a file or a pipe.
pub fn interval(tty: bool) -> Duration {
    Duration::from_secs(if tty { 2 } else { 10 })
}

struct State {
    start: Instant,
    pacer: Pacer,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static CALLS: AtomicU64 = AtomicU64::new(0);

/// Begin reporting for one command. `quiet` turns it off.
pub fn start(quiet: bool) {
    use std::io::IsTerminal;
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    *g = if quiet { None } else { Some(State { start: Instant::now(), pacer: Pacer::new(interval(std::io::stderr().is_terminal())) }) };
}

pub fn stop() {
    *STATE.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Print `line()` to stderr if a line is due. `line` receives the elapsed time ("1m 05s").
pub fn tick(line: impl FnOnce(&str) -> String) {
    // the clock is read every 64th call; a walk makes thousands of calls a second
    if !CALLS.fetch_add(1, Ordering::Relaxed).is_multiple_of(64) {
        return;
    }
    tick_now(line);
}

/// Like `tick`, for loops whose steps are slow (a repo, a host): every call checks the clock.
pub fn tick_now(line: impl FnOnce(&str) -> String) {
    let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(s) = g.as_mut() else { return };
    let el = s.start.elapsed();
    if s.pacer.due(el) {
        eprintln!("{}", line(&crate::collect::util::secs(el.as_secs())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_is_due_every_interval_and_not_before() {
        let mut p = Pacer::new(interval(true));
        assert!(!p.due(Duration::from_millis(1900)));
        assert!(p.due(Duration::from_secs(2)));
        assert!(!p.due(Duration::from_millis(3900)));
        assert!(p.due(Duration::from_secs(4)));
        let mut q = Pacer::new(interval(false));
        assert!(!q.due(Duration::from_secs(9)));
        assert!(q.due(Duration::from_secs(10)));
        // a long silence gives one line, not a burst
        assert!(q.due(Duration::from_secs(95)));
        assert!(!q.due(Duration::from_secs(96)));
    }
}
