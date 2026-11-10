//! satori-core: Satori's Nostr domain layer.
//!
//! The web app reference lives in `src/` at the repo root (frozen). Each module's
//! doc comment names the TypeScript file(s) whose *semantics* it ports. This crate
//! must never depend on GTK: the UI (`crates/app`) is a projection of the state
//! managed here (DESIGN.md §1.2 — HATEOAS, natively).
//!
//! Signing is local (bunker via NIP-46, or an opt-in local key in the Secret
//! Service). The web app's entire NIP-07 sign-and-resubmit seam is deliberately
//! absent (DESIGN.md §2).

#![allow(dead_code)]

pub mod blocktime;
pub mod config;
pub mod dedup;
pub mod deletions;
pub mod diag;
pub mod error;
pub mod hints;
pub mod manager;
pub mod net_guard;
pub mod nip11;
pub mod nip40;
pub mod privacy;
pub mod profiles;
pub mod read_state;
pub mod secrets;
pub mod session;
pub mod socks;
pub mod signer;
pub mod undo;

pub mod dms;
pub mod engagement;
pub mod video_proxy;
pub mod viewport;
pub mod kinds;
pub mod media;
pub mod nip;
pub mod notifications;
pub mod outbox;
pub mod outbox_queue;
pub mod pool;
pub mod publish;
pub mod rate;
pub mod relay_latency;
pub mod scheduled;
pub mod seen;
pub mod store;
pub mod tor;
pub mod upload;
pub mod wallet;
pub mod wot;

#[cfg(test)]
pub(crate) mod test_env {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// Tests that touch prefs/secrets on disk serialize here (the env is
    /// process-global; parallel runs delete each other's state).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII over the process-global test env: holds ENV_LOCK for the
    /// guard's lifetime and points XDG_DATA_HOME at a fresh, private
    /// directory. On drop (normal OR unwind), the env is restored and the
    /// directory removed - no state leaks into later tests, and no test
    /// inherits a previous test's leaked value.
    ///
    /// The lock is taken poison-tolerantly: one env test failing used to
    /// poison the mutex and cascade "poisoned lock" panics into every
    /// later env test, masking the real failure.
    pub struct EnvGuard {
        _lock: Option<MutexGuard<'static, ()>>,
        prior: Option<OsString>,
        dir: PathBuf,
    }

    impl EnvGuard {
        /// Isolate the data dir under a tag-named directory
        /// (`satori-env-{tag}-{pid}`): unique per test binary process,
        /// reused only after a clean previous run.
        pub fn new(tag: &str) -> Self {
            let lock = Some(ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner));
            let prior = std::env::var_os("XDG_DATA_HOME");
            let dir =
                std::env::temp_dir().join(format!("satori-env-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("create isolated test data dir");
            unsafe { std::env::set_var("XDG_DATA_HOME", &dir) };
            Self { _lock: lock, prior, dir }
        }

        /// The isolated data dir (tests plant state here, never in $HOME).
        pub fn dir(&self) -> &PathBuf {
            &self.dir
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match self.prior.take() {
                    Some(p) => std::env::set_var("XDG_DATA_HOME", p),
                    None => std::env::remove_var("XDG_DATA_HOME"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}
