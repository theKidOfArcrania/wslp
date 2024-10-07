use anyhow::anyhow;
use cgmath::{MetricSpace, Vector2, Vector3, Zero};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env::args,
    future::Future,
    net::SocketAddr,
    ops::DerefMut,
    pin::Pin,
    process::exit,
    str::from_utf8,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex as SMutex, OnceLock,
    },
    task::Poll,
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net, signal,
    sync::{Mutex, Notify},
    task::{spawn_blocking, JoinHandle, JoinSet},
    time,
};

const MAX_BUFFER: usize = 0x1000;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static INTERRUPTED_NOTIFY: Notify = Notify::const_new();

static FLAGS: OnceLock<[String; 2]> = OnceLock::new();

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

macro_rules! file_def {
    ($($getter: ident => $file:literal;)*) => {
        $(
            pub fn $getter() -> anyhow::Result<&'static str> {
                static DATA: OnceLock<String> = OnceLock::new();
                Ok(DATA.get_or_try_init(|| -> anyhow::Result<_> {
                    Ok(std::fs::read_to_string($file)?)
                })?)
            }
        )*
    }
}

file_def! {
    get_flag1 => "flag1.txt";
    //get_flag2 => "flag2.txt";
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

pub struct RW<R: AsyncBufReadExt, W: AsyncWriteExt> {
    pub read: R,
    pub write: W,
    rbuff: Vec<u8>,
    rbuff_ret: Vec<u8>,
}

impl<R: AsyncBufReadExt + Unpin, W: AsyncWriteExt + Unpin> RW<R, W> {
    pub fn new(read: R, write: W) -> Self {
        RW {
            read,
            write,
            rbuff: Vec::new(),
            rbuff_ret: Vec::new(),
        }
    }

    pub async fn wait_for_eof<X>(&mut self) -> anyhow::Result<X> {
        let mut chunk = vec![0; MAX_BUFFER];
        loop {
            let read = self.read.read(&mut chunk).await?;
            if read == 0 {
                anyhow::bail!("Peer sent EOF");
            }
            if self.rbuff.len() >= MAX_BUFFER {
                // Feel free to drop this chunk... them bozos just spamming us
                // with a lot of data so they probably don't care if we retain
                // these bytes...
                continue;
            }

            let copylen = read.min(MAX_BUFFER - self.rbuff.len());
            self.rbuff.extend_from_slice(&chunk[0..copylen])
        }
    }

    pub async fn send(&mut self, data: &str) -> anyhow::Result<()> {
        self.write.write(data.as_bytes()).await?;
        self.write.flush().await?;
        Ok(())
    }

    pub async fn recvline(&mut self) -> anyhow::Result<&str> {
        self.rbuff_ret.clear();
        if let Some((line, _)) = self.rbuff.split_once(|c| *c == b'\n') {
            self.rbuff_ret.extend_from_slice(line);
            let range = line.len() + 1..self.rbuff.len();
            self.rbuff.copy_within(range, 0);
        } else {
            self.read.read_until(b'\n', &mut self.rbuff).await?;
            self.rbuff_ret.extend_from_slice(&self.rbuff);
            self.rbuff.clear();
        }

        Ok(from_utf8(&self.rbuff_ret)?.trim_end_matches(|c| c == '\n' || c == '\r'))
    }

    pub async fn recvlineafter(&mut self, prompt: &str) -> anyhow::Result<&str> {
        self.send(prompt).await?;
        self.recvline().await
    }
}

pub trait FutureExt<T> {
    async fn interruptable(
        self,
        ctx: &(dyn std::fmt::Display + Sync),
        action: &str,
    ) -> anyhow::Result<T>;

    async fn timed(self, timeout: time::Instant) -> Option<T>;
}

impl<T, F: Future<Output = T>> FutureExt<T> for F {
    async fn interruptable(
        self,
        ctx: &(dyn std::fmt::Display + Sync),
        action: &str,
    ) -> anyhow::Result<T> {
        tokio::select! {
            res = self => { Ok(res) }
            _ = wait_for_interrupt() => {
                anyhow::bail!("{ctx}: Interrupted while {action}!");
            }
        }
    }

    async fn timed(self, timeout: time::Instant) -> Option<T> {
        tokio::select! {
            res = self => { Some(res) }
            _ = time::sleep_until(timeout) => None
        }
    }
}

pub async fn try_finally<T, F>(
    action: impl Future<Output = anyhow::Result<T>>,
    finally_case: impl Fn(bool) -> F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<()>>,
{
    let res = action.await;
    let fres = finally_case(res.is_ok()).await;
    match res {
        Ok(res) => {
            fres?;
            Ok(res)
        }
        Err(e) => Err(match fres {
            Ok(()) => e,
            Err(fe) => e.context(fe),
        }),
    }
}

pub struct SharedFuture<F> {
    future: Arc<Mutex<Pin<Box<F>>>>,
}

impl<F> Clone for SharedFuture<F> {
    fn clone(&self) -> Self {
        Self {
            future: self.future.clone(),
        }
    }
}

impl<F: Future<Output = O>, O> SharedFuture<F> {
    pub fn new(future: F) -> Self {
        Self {
            future: Arc::new(Mutex::new(Box::pin(future))),
        }
    }

    pub async fn get(&self) -> O {
        self.future.lock().await.deref_mut().await
    }
}
