//! In-memory throttling for credential endpoints.
//!
//! Failures are counted per client address and per (client address, email) instead of per
//! account alone, so an anonymous client cannot lock somebody else out by guessing wrong.
//! The persistent account lock in PostgreSQL remains as a much higher backstop against
//! distributed guessing.
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Credential requests one client address may send before it is slowed down.
const REQUEST_BURST: f64 = 20.0;
/// Sustained credential requests per minute per client address.
const REQUESTS_PER_MINUTE: f64 = 20.0;
/// Failed sign-ins for one email from one client address before that pair is paused.
const PAIR_FAILURES: u32 = 5;
/// Failed sign-ins from one client address, across all emails, before it is paused.
const CLIENT_FAILURES: u32 = 30;
const FAILURE_WINDOW: Duration = Duration::from_mins(15);
/// Bounds memory if many distinct addresses or emails are seen.
const MAX_ENTRIES: usize = 50_000;

#[derive(Default)]
pub struct Throttle {
    inner: Mutex<State>,
}

#[derive(Default)]
struct State {
    buckets: HashMap<IpAddr, Bucket>,
    clients: HashMap<IpAddr, Failures>,
    pairs: HashMap<(IpAddr, String), Failures>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

struct Failures {
    count: u32,
    since: Instant,
}

impl Default for Failures {
    fn default() -> Self {
        Self {
            count: 0,
            since: Instant::now(),
        }
    }
}

impl Failures {
    /// Counts one failure, starting a new window once the previous one has elapsed.
    fn bump(&mut self, now: Instant) {
        if self.current(now) == 0 {
            self.count = 0;
            self.since = now;
        }
        self.count += 1;
    }

    fn current(&self, now: Instant) -> u32 {
        if now.duration_since(self.since) >= FAILURE_WINDOW {
            0
        } else {
            self.count
        }
    }

    fn retry_after(&self, now: Instant) -> Duration {
        FAILURE_WINDOW.saturating_sub(now.duration_since(self.since))
    }
}

impl Throttle {
    /// Spends one credential request for `client`. Returns how long to wait when the
    /// client has exhausted its budget.
    pub fn admit(&self, client: IpAddr) -> Result<(), Duration> {
        let now = Instant::now();
        let mut state = self.lock();
        state.prune(now);
        let bucket = state.buckets.entry(client).or_insert(Bucket {
            tokens: REQUEST_BURST,
            updated: now,
        });
        let refill = now.duration_since(bucket.updated).as_secs_f64() * REQUESTS_PER_MINUTE / 60.0;
        bucket.tokens = (bucket.tokens + refill).min(REQUEST_BURST);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            let wait = (1.0 - bucket.tokens) * 60.0 / REQUESTS_PER_MINUTE;
            return Err(Duration::from_secs_f64(wait.ceil().max(1.0)));
        }
        bucket.tokens -= 1.0;
        Ok(())
    }

    /// Returns how long `client` must wait before trying `email` again, if it is paused.
    /// The answer depends only on this client's own failures, never on whether the account
    /// exists, so it reveals nothing about other users.
    pub fn sign_in_paused(&self, client: IpAddr, email: &str) -> Option<Duration> {
        let now = Instant::now();
        let state = self.lock();
        let pair = state
            .pairs
            .get(&(client, email.to_owned()))
            .filter(|f| f.current(now) >= PAIR_FAILURES)
            .map(|f| f.retry_after(now));
        let any = state
            .clients
            .get(&client)
            .filter(|f| f.current(now) >= CLIENT_FAILURES)
            .map(|f| f.retry_after(now));
        pair.max(any)
    }

    pub fn record_failure(&self, client: IpAddr, email: &str) {
        let now = Instant::now();
        let mut state = self.lock();
        state.clients.entry(client).or_default().bump(now);
        state
            .pairs
            .entry((client, email.to_owned()))
            .or_default()
            .bump(now);
    }

    pub fn record_success(&self, client: IpAddr, email: &str) {
        self.lock().pairs.remove(&(client, email.to_owned()));
    }

    #[cfg(test)]
    pub fn clear(&self) {
        *self.lock() = State::default();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl State {
    fn prune(&mut self, now: Instant) {
        if self.buckets.len() + self.clients.len() + self.pairs.len() < MAX_ENTRIES {
            return;
        }
        self.buckets
            .retain(|_, b| now.duration_since(b.updated) < Duration::from_secs(120));
        self.clients.retain(|_, f| f.current(now) > 0);
        self.pairs.retain(|_, f| f.current(now) > 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));

    #[test]
    fn one_clients_failures_never_pause_another_client() {
        let throttle = Throttle::default();
        for _ in 0..PAIR_FAILURES {
            throttle.record_failure(A, "admin@example.test");
        }
        assert!(throttle.sign_in_paused(A, "admin@example.test").is_some());
        assert_eq!(throttle.sign_in_paused(B, "admin@example.test"), None);
        assert_eq!(throttle.sign_in_paused(A, "other@example.test"), None);
    }

    #[test]
    fn spraying_many_emails_pauses_the_client() {
        let throttle = Throttle::default();
        for i in 0..CLIENT_FAILURES {
            throttle.record_failure(A, &format!("user{i}@example.test"));
        }
        assert!(throttle.sign_in_paused(A, "fresh@example.test").is_some());
        assert_eq!(throttle.sign_in_paused(B, "fresh@example.test"), None);
    }

    #[test]
    fn success_clears_only_that_pair() {
        let throttle = Throttle::default();
        for _ in 0..PAIR_FAILURES - 1 {
            throttle.record_failure(A, "member@example.test");
        }
        throttle.record_success(A, "member@example.test");
        throttle.record_failure(A, "member@example.test");
        assert_eq!(throttle.sign_in_paused(A, "member@example.test"), None);
    }

    #[test]
    fn request_budget_refuses_bursts_beyond_the_limit() {
        let throttle = Throttle::default();
        for _ in 0..20 {
            assert!(throttle.admit(A).is_ok());
        }
        assert!(throttle.admit(A).is_err());
        assert!(throttle.admit(B).is_ok());
    }
}
