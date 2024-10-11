use std::{
    future::Future,
    process::exit,
    sync::atomic::{AtomicBool, Ordering},
};
use tokio::{signal, sync::Notify, time};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static INTERRUPTED_NOTIFY: Notify = Notify::const_new();

pub fn init() {
    tokio::spawn(async {
        signal::ctrl_c()
            .await
            .expect("Failed to listen to ctrl+c event");

        log::info!("Shuting down server... Ctrl+C again to force shutdown without cleanup");
        INTERRUPTED.store(true, Ordering::Relaxed);
        INTERRUPTED_NOTIFY.notify_waiters();

        signal::ctrl_c()
            .await
            .expect("Failed to listen to ctrl+c event");
        log::info!("Force shutting down...");
        exit(0);
    });
}

pub fn signal_interrupt() {
    INTERRUPTED.store(true, Ordering::Relaxed);
    INTERRUPTED_NOTIFY.notify_waiters();
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

pub async fn wait_for_interrupt() {
    let waiter = INTERRUPTED_NOTIFY.notified();
    tokio::pin!(waiter);
    waiter.as_mut().enable();

    while !interrupted() {
        waiter.as_mut().await;
        return;
    }
}

pub trait FutureExt<T> {
    async fn timed(self, timeout: time::Instant) -> Option<T>;
}

impl<T, F: Future<Output = T>> FutureExt<T> for F {
    async fn timed(self, timeout: time::Instant) -> Option<T> {
        tokio::select! {
            res = self => { Some(res) }
            _ = time::sleep_until(timeout) => None
        }
    }
}
