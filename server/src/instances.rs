use std::sync::atomic::{AtomicU8, Ordering};

const MAX_INSTANCES: u8 = 10;

static INSTANCES: AtomicU8 = AtomicU8::new(0);
pub struct InstanceAllocator(());
impl InstanceAllocator {
    pub fn get() -> Option<Self> {
        let mut running = INSTANCES.load(Ordering::SeqCst);
        loop {
            if running >= MAX_INSTANCES {
                return None;
            }

            match INSTANCES.compare_exchange_weak(
                running,
                running + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(x) => running = x,
            }
        }

        Some(Self(()))
    }
}

impl Drop for InstanceAllocator {
    fn drop(&mut self) {
        INSTANCES.fetch_sub(1, Ordering::SeqCst);
    }
}
