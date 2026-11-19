//! Small shared helpers.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Lock a mutex even if another thread panicked while holding it. The data
/// guarded here (result lists, caches, status) stays usable after a panic,
/// and one failed worker must not take the window down with it.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
