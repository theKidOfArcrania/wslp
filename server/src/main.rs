#![feature(once_cell_try)]
#![feature(array_try_map)]
#![feature(slice_split_once)]

use anyhow::anyhow;
use cgmath::{MetricSpace, Vector2, Vector3, Zero};
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque}, env::args, future::Future, mem::swap, net::SocketAddr, ops::DerefMut, pin::Pin, process::exit, str::from_utf8, sync::{
        atomic::{AtomicBool, Ordering}, Arc, Condvar, Mutex as SMutex, OnceLock
    }, task::Poll
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net, signal,
    sync::{Mutex, Notify},
    task::{spawn_blocking, JoinHandle, JoinSet},
    time::{self, Instant},
};
use vmm::{PSBool, PSState, StartAction, StopAction};

// 20000 diff ~ 8sec
const DIFFICULTY: u32 = 20;

const HOST_IP: &str = "10.69.0.1";
const HOST_PORT_MULTIPLEX: u16 = 31337;
const HOST_PORT_ENTRY: u16 = 20000;

const COLOR_LOGIN: Vector3<f32> = Vector3::new(0.0, 0.11, 0.533);
const COLOR_LOGIN2: Vector3<f32> = Vector3::new(0.031, 0.169, 0.788);
const COLOR_LOGIN_FIELD: Vector3<f32> = Vector3::new(0.094, 0.11, 0.22);
const COLOR_TERM: Vector3<f32> = Vector3::new(0.031, 0.047, 0.031);
const COLOR_TASKBAR: Vector3<f32> = Vector3::new(0.91, 0.925, 0.91);
const COLOR_WINRUN: Vector3<f32> = Vector3::new(0.941, 0.941, 0.941);

const LOGIN_X: usize = 40;
const LOGIN_Y: usize = 13;
const LOGIN_SZ: usize = 5;
const LOGIN_FIELD_X: usize = 50;
const LOGIN_FIELD_Y: usize = 54;
const TASKBAR_TOP: usize = 83;
const TASKBAR_BOT: usize = 87;
const TASKBAR_X: usize = 20;
const TASKBAR_W: usize = 5;
const WINRUN_X: usize = 8;
const WINRUN_Y: usize = 63;

mod instances;
mod vmm;
pub mod wmi_ext;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static INTERRUPTED_NOTIFY: Notify = Notify::const_new();

fn hook_interrupt() {
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

static FLAGS: OnceLock<[String; 2]> = OnceLock::new();

fn get_flags() -> anyhow::Result<[&'static str; 2]> {
    let [flag1, flag2] = FLAGS.get_or_try_init(|| -> anyhow::Result<_> {
        let flag1 = std::fs::read_to_string("flag1.txt")?;
        let flag2 = std::fs::read_to_string("flag2.txt")?;
        Ok([flag1, flag2])
    })?;

    Ok([flag1, flag2])
}

const MAX_BUFFER: usize = 0x1000;

struct RW<R: AsyncBufReadExt, W: AsyncWriteExt> {
    read: R,
    write: W,
    rbuff: Vec<u8>,
    rbuff_ret: Vec<u8>,
}

impl<R: AsyncBufReadExt + Unpin, W: AsyncWriteExt + Unpin> RW<R, W> {
    fn new(read: R, write: W) -> Self {
        RW {
            read,
            write,
            rbuff: Vec::new(),
            rbuff_ret: Vec::new(),
        }
    }

    async fn wait_for_eof<X>(&mut self) -> anyhow::Result<X> {
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

    async fn send(&mut self, data: &str) -> anyhow::Result<()> {
        self.write.write(data.as_bytes()).await?;
        self.write.flush().await?;
        Ok(())
    }

    async fn recvline(&mut self) -> anyhow::Result<&str> {
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

    async fn recvlineafter(&mut self, prompt: &str) -> anyhow::Result<&str> {
        self.send(prompt).await?;
        self.recvline().await
    }
}

enum PeerState {
    Connecting(usize),
    PartialConnected(net::TcpStream),
    FullyConnected,
}

#[derive(Default)]
struct VmSession {
    vm: Option<vmm::Vm>,
    server_peer: Option<net::TcpStream>,
    peers: Vec<PeerState>,
}

struct VmSessionsMgr {
    sessions: Mutex<BTreeMap<u128, VmSession>>,
    shared: Mutex<BTreeSet<u128>>,
    peer_notify: Notify,
}

impl VmSessionsMgr {
    pub const fn new() -> Self {
        Self {
            sessions: Mutex::const_new(BTreeMap::new()),
            shared: Mutex::const_new(BTreeSet::new()),
            peer_notify: Notify::const_new(),
        }
    }

    pub async fn shared_vms(&self) -> BTreeSet<u128> {
        self.shared.lock().await.clone()
    }

    pub async fn register_new(&self, shared: bool) -> u128 {
        let mut key = rand::random();
        let mut sessions = self.sessions.lock().await;
        while sessions.contains_key(&key) {
            key = rand::random();
        }
        sessions.insert(key, VmSession::default());
        drop(sessions);

        if shared {
            self.shared.lock().await.insert(key);
        }

        key
    }

    pub async fn unregister(&self, key: &u128) -> anyhow::Result<()> {
        let sess = self.sessions.lock().await.remove(&key);
        if let Some(vm) = sess.and_then(|sess| sess.vm) {
            vm.cleanup().await?;
        } else {
            log::warn!("VM 0x{key:032x} does not have associated initialized VM with it");
        }

        self.shared.lock().await.remove(&key);
        Ok(())
    }

    pub async fn associate_vm(&self, key: &u128, vm: vmm::Vm) {
        let mut sessions = self.sessions.lock().await;
        if let Some(sess) = sessions.get_mut(&key) {
            // Only change VM if it isn't already written to.
            if sess.vm.is_none() {
                sess.vm = Some(vm);
            }
        }
    }

    pub async fn connect_server_peer(&self, key: &u128) -> anyhow::Result<()> {
        let mpa = self.open_peer(key).await?;

        let mut sessions = self.sessions.lock().await;
        let Some(sess) = sessions.get_mut(&key) else {
            anyhow::bail!("VM 0x{key:032x} does not exist");
        };

        let Some(vm) = &sess.vm else {
            anyhow::bail!("VM 0x{key:032x} has not been initialized");
        };

        let vm = vm.clone();
        drop(sessions);
        vm.start_wsl(&mpa).await?;

        let client = self.wait_for_peer(key, mpa.port).await?;

        self.sessions
            .lock()
            .await
            .get_mut(&key)
            .expect("Should exist")
            .server_peer = Some(client);

        Ok(())
    }

    pub async fn connect_client_peer(&self, key: &u128) -> anyhow::Result<net::TcpStream> {
        let mpa = self.open_peer(key).await?;

        let mut sessions = self.sessions.lock().await;
        let Some(sess) = sessions.get_mut(&key) else {
            anyhow::bail!("VM 0x{key:032x} does not exist");
        };

        let Some(server) = &mut sess.server_peer else {
            anyhow::bail!("VM 0x{key:032x} server peer has not been initialized")
        };

        server.write_all(mpa.bash_string().as_bytes()).await?;
        server.write_u8(b'\n').await?;
        server.flush().await?;

        self.wait_for_peer(key, mpa.port).await
    }

    pub async fn open_peer(&self, key: &u128) -> anyhow::Result<MultiplexAddr> {
        let mut sessions = self.sessions.lock().await;
        let Some(sess) = sessions.get_mut(&key) else {
            anyhow::bail!("VM 0x{key:032x} does not exist");
        };

        let mut rng = rand::thread_rng();
        let port_key = rng.gen();
        sess.peers.push(PeerState::Connecting(port_key));
        Ok(MultiplexAddr {
            key: *key,
            port: sess.peers.len() - 1,
            port_key,
        })
    }

    pub async fn connect_peer(
        &self,
        conn: &MultiplexAddr,
        peer_stream: &mut Option<net::TcpStream>,
    ) -> anyhow::Result<()> {
        let mut sessions = self.sessions.lock().await;
        let Some(sess) = sessions.get_mut(&conn.key) else {
            anyhow::bail!("VM 0x{:032x} does not exist", conn.key);
        };

        let Some(peer) = sess.peers.get_mut(conn.port).filter(|peer| match peer {
            PeerState::Connecting(port_key) => conn.port_key == *port_key,
            _ => false,
        }) else {
            anyhow::bail!(
                "Invalid port {:032x}:{}:{:016x}",
                conn.key,
                conn.port,
                conn.port_key
            );
        };

        *peer = PeerState::PartialConnected(peer_stream.take().expect("Should not be empty"));
        self.peer_notify.notify_waiters();

        Ok(())
    }

    pub async fn wait_for_peer(&self, key: &u128, port: usize) -> anyhow::Result<net::TcpStream> {
        log::info!("{key:032x}: Waiting for peer connection to port {port}");
        loop {
            let mut sessions = self.sessions.lock().await;
            let Some(sess) = sessions.get_mut(&key) else {
                anyhow::bail!("VM 0x{key:032x} does not exist");
            };

            let Some(peer) = sess.peers.get_mut(port) else {
                anyhow::bail!("Invalid port {key:032x}:{port}");
            };

            let mut cur_peer = PeerState::FullyConnected;
            swap(peer, &mut cur_peer);

            match cur_peer {
                PeerState::Connecting(client) => {
                    *peer = PeerState::Connecting(client);
                }
                PeerState::PartialConnected(stream) => {
                    return Ok(stream);
                }
                PeerState::FullyConnected => {
                    anyhow::bail!("Peer port {key:032x}:{port} is already fully connected!");
                }
            }

            let waiter = self.peer_notify.notified();
            tokio::pin!(waiter);
            waiter.as_mut().enable();
            drop(sessions);

            waiter.await;
        }
    }
}

static VM_SESS_MGR: VmSessionsMgr = VmSessionsMgr::new();

trait FutureExt<T> {
    async fn interruptable(
        self,
        ctx: &(dyn std::fmt::Display + Sync),
        action: &str,
    ) -> anyhow::Result<T>;

    async fn timed(self, timeout: Instant) -> Option<T>;
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

    async fn timed(self, timeout: Instant) -> Option<T> {
        tokio::select! {
            res = self => { Some(res) }
            _ = time::sleep_until(timeout) => None
        }
    }
}

async fn partition_vm(
    name: String,
    vhd_src: &str,
    shared: bool,
) -> anyhow::Result<(u128, vmm::Vm)> {
    if !vhd_src.ends_with(".vhdx") {
        anyhow::bail!("VHD should end in .vhdx");
    }
    let vhd_path = format!("{name}/disk.vhdx");

    let created_key = Arc::new(Mutex::new(None));
    try_finally(
        async {
            fs::create_dir(&name).await?;
            let vhd_path = if vhd_src.contains("debug") {
                log::warn!("Skipping copying base files because vhd is debug");
                vhd_src
            } else {
                log::info!("VM {name}: Copying base files");
                fs::copy(&vhd_src, &vhd_path).await?;
                if interrupted() {
                    anyhow::bail!("VM {name}: Interrupted while copying files!");
                }
                &vhd_path
            };

            let key = VM_SESS_MGR.register_new(shared).await;
            log::info!("VM {name}: Registered VM -> 0x{key:032x}");

            *created_key.lock().await = Some(key);

            log::info!("VM {name}: Creating VM...");
            let vm = vmm::VmBuilder::default()
                .backing_path(name.clone())
                .name(name.clone())
                .use_gen2()
                .memory_startup_bytes("1GB".into())
                .existing_vhd(vhd_path.into())
                .path(format!("{name}/vm"))
                .boot_device(vmm::BootDevice::VHD)
                .build()
                .interruptable(&name, "creating VM")
                .await??;

            VM_SESS_MGR.associate_vm(&key, vm.clone()).await;

            log::info!("VM {name}: Configuring VM...");
            vm.set_bundled()
                .set(&vmm::attrs::AutomaticCheckpointsEnabled, PSBool(false))
                .set(&vmm::attrs::AutomaticStartAction, StartAction::Nothing)
                .set(&vmm::attrs::AutomaticStopAction, StopAction::TurnOff)
                .set(&vmm::attrs::ProcessorCount, 1)
                .set(&vmm::attrs::ExposeVirtualizationExtensions, PSBool(true))
                .set(&vmm::attrs::EnableSecureBoot, PSState::On)
                .commit()
                .interruptable(&name, "configuring VM")
                .await??;

            vm.add_network("HostOnly".into())
                .interruptable(&name, "adding network")
                .await??;

            log::info!("VM {name}: Configuration completed!");
            Ok((key, vm))
        },
        |is_success| {
            let name = name.clone();
            let created_key = created_key.clone();
            async move {
                if !is_success {
                    log::warn!("VM {name}: Performing cleanup for VM due to error...");
                    let res = if let Some(key) = &*created_key.lock().await {
                        log::info!("VM {name}: ...by unregistering VM");
                        VM_SESS_MGR.unregister(key).await
                    } else {
                        log::info!("VM {name}: ...by removing the directory");
                        fs::remove_dir_all(&name).await.map_err(|e| e.into())
                    };

                    match res {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("VM {name}: Unable to cleanup completely: {e}\n{}", e.backtrace())
                        }
                    }
                }
                Ok(())
            }
        },
    )
    .await
}

async fn try_finally<T, F>(
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
        Err(e) => {
            Err(match fres {
                Ok(()) => e,
                Err(fe) => e.context(fe)
            })
        }
    }
}

async fn client_auth<R, W>(client: &mut RW<R, W>) -> anyhow::Result<Option<bool>>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Call PoW
    let pow = kctf_pow::KctfPow::new();
    let chall = pow.generate_challenge(DIFFICULTY);
    let prompt = format!("./kctf-pow solve {}\n> ", chall.to_string(),);
    match chall.check(client.recvlineafter(&prompt).await?) {
        Ok(true) => {}
        _ => {
            client.send("Bad PoW response\n").await?;
            return Ok(None);
        }
    }

    // Check flag
    let [flag1, _] = get_flags()?;
    let flag = client.recvlineafter("Flag from part 1: ").await?;
    let is_admin = if flag.trim() == flag1.trim() {
        false
    } else if flag == "ADMIN_ADMIN!!!!_6G93ugsoi;jsjfaie" {
        client.send("Admin mode activated!\n").await?;
        true
    } else {
        client.send("Wrong flag\n").await?;
        return Ok(None);
    };

    Ok(Some(is_admin))
}

fn snapshot(vssd_path: &str, width: i16, height: i16) -> anyhow::Result<Option<Vec<Vector3<f32>>>> {
    const FRAC: f32 = 1.0 / 256.0;

    let vsm = wmi_ext::VirtualSystemManagementService::singleton()?;
    let vssd = wmi_ext::VirtualSystemSettingData::new(vssd_path.into());
    let data = vsm.get_virtual_system_thumbnail_image(&vssd, width, height)?;
    if data.len() == 0 {
        return Ok(None);
    }

    let mut ret = Vec::new();
    let data = bytemuck::cast_slice::<_, u16>(&data[4..]);
    for &pixel in data {
        let b = (pixel << 3) as u8 as f32 * FRAC;
        let g = ((pixel >> 3) & !3) as u8 as f32 * FRAC;
        let r = ((pixel >> 8) & !7) as u8 as f32 * FRAC;
        ret.push(Vector3::new(r, g, b));
    }

    Ok(Some(ret))
}

#[derive(Debug)]
enum KeyboardJobType {
    TypeCtrlAltDel(),
    TypeText(String),
    PressKey(u32),
    ReleaseKey(u32),
    //TypeKey(u32),
}

struct KeyboardJob {
    tp: KeyboardJobType,
    notify: Notify,
}

impl KeyboardJob {
    fn new(tp: KeyboardJobType) -> Arc<Self> {
        Arc::new(Self {
            tp,
            notify: Notify::new(),
        })
    }
}

struct SharedFuture<F> {
    future: Arc<Mutex<Pin<Box<F>>>>,
}

impl<F> Clone for SharedFuture<F> {
    fn clone(&self) -> Self {
        Self { future: self.future.clone() }
    }
}

impl<F: Future<Output = O>, O> SharedFuture<F> {
    pub fn new(future: F) -> Self {
        Self { future: Arc::new(Mutex::new(Box::pin(future))) }
    }

    pub async fn get(&self) -> O {
        self.future
            .lock()
            .await
            .deref_mut()
            .await
    }
}

#[derive(Default)]
struct KeyboardJobState {
    running_notify: Notify,
    stopping: AtomicBool,
    jobs: SMutex<VecDeque<Arc<KeyboardJob>>>,
    job_notify: Condvar,
}

struct KeyboardJobSet {
    join: SharedFuture<JoinHandle<anyhow::Result<()>>>,
    state: Arc<KeyboardJobState>,
}

macro_rules! keyjob {
    ($($fn:ident($($arg:ident: $tp:ty)*) -> $enum:ident;)*) => {
        $(
            pub async fn $fn(&self $(, $arg: $tp)*) -> anyhow::Result<()> {
                self.submit_job(KeyboardJobType::$enum($($arg)*)).await
            }
        )*
    }
}

impl Drop for KeyboardJobSet {
    fn drop(&mut self) {
        self.state.stopping.store(true, Ordering::Relaxed);
        self.state.job_notify.notify_one();
    }
}

impl KeyboardJobSet {
    pub async fn new(vm: &vmm::Vm) -> anyhow::Result<Self> {
        let vm = vm.clone();
        let state = Arc::new(KeyboardJobState::default());

        let state2 = state.clone();
        let join = spawn_blocking(move || {
            let kb = vm.try_get_keyboard()?;
            state2.running_notify.notify_one();
            while !state2.stopping.load(Ordering::Relaxed) {
                let mut state_lock = state2.jobs.lock().unwrap();
                let job = match state_lock.pop_front() {
                    Some(job) => {
                        drop(state_lock);
                        job
                    }
                    None => {
                        let res = state2.job_notify.wait(state_lock).unwrap().pop_front();
                        match res {
                            Some(job) if !state2.stopping.load(Ordering::Relaxed) => job,
                            _ => continue,
                        }
                    }
                };

                let _ = match &job.tp {
                    KeyboardJobType::TypeCtrlAltDel() => kb.type_ctrl_alt_del(),
                    KeyboardJobType::TypeText(msg) => kb.type_text(msg.clone()),
                    &KeyboardJobType::PressKey(kc) => kb.press_key(kc),
                    &KeyboardJobType::ReleaseKey(kc) => kb.release_key(kc),
                    //&KeyboardJobType::TypeKey(kc) => kb.type_key(kc),
                }?;

                job.notify.notify_one();
            }
            Ok(())
        });

        let join = SharedFuture::new(join);
        let join2 = join.clone();
        tokio::select! {
            _ = state.running_notify.notified() => { () }
            joinres = join2.get() => {
                joinres??;
                anyhow::bail!("Job has already been aborted");
            }
        };

        Ok(Self {
            state,
            join,
        })
    }

    pub async fn submit_job(&self, job: KeyboardJobType) -> anyhow::Result<()> {
        let job = KeyboardJob::new(job);
        let join = self.join.clone();
        self.state.jobs.lock().unwrap().push_back(job.clone());
        self.state.job_notify.notify_one();
        tokio::select! {
            _ = job.notify.notified() => { () }
            joinres = join.get() => {
                joinres??;
                anyhow::bail!("Job has already been aborted");
            }
        };
        Ok(())
    }

    keyjob! {
        type_ctrl_alt_del() -> TypeCtrlAltDel;
        type_text(msg: String) -> TypeText;
        press_key(kc: u32) -> PressKey;
        release_key(kc: u32) -> ReleaseKey;
        //type_key(kc: u32) -> TypeKey;
    }

    pub async fn stop(self) -> anyhow::Result<()> {
        self.state.stopping.store(true, Ordering::Relaxed);
        self.state.job_notify.notify_one();
        self.join.get().await?
    }
}

impl vmm::Vm {
    async fn get_keyboard_async(&self) -> anyhow::Result<KeyboardJobSet> {
        KeyboardJobSet::new(self).await
    }

    async fn wait_for_region(
        &self,
        top: Vector2<usize>,
        size: Vector2<usize>,
        target: Vector3<f32>,
    ) -> anyhow::Result<()> {
        self.wait_for_region_set(top, size, vec![target]).await
    }

    async fn wait_for_region_set(
        &self,
        top: Vector2<usize>,
        size: Vector2<usize>,
        targets: Vec<Vector3<f32>>,
    ) -> anyhow::Result<()> {
        loop {
            let color = region_color(
                self.get_vssd_path()?,
                100,
                100,
                top,
                size,
            )?;
            if color_matches(color, &targets) {
                return Ok(());
            }

            time::sleep(time::Duration::from_secs_f32(0.1)).await;
        }
    }

    async fn input_credentials(&self, pwd: &str) -> anyhow::Result<()> {
        let kb = self.get_keyboard_async().await?;
        kb.type_ctrl_alt_del().await?;

        log::info!("VM {}: Waiting for login field to load", self.name());
        self.wait_for_region(
            Vector2::new(LOGIN_FIELD_X, LOGIN_FIELD_Y),
            Vector2::new(1, 1),
            COLOR_LOGIN_FIELD,
        ).await?;

        kb.type_text(format!("{pwd}\n")).await?;
        kb.stop().await?;

        log::info!("VM {}: Waiting for taskbar to load", self.name());
        self.wait_for_region(
            Vector2::new(TASKBAR_X, TASKBAR_TOP),
            Vector2::new(TASKBAR_W, TASKBAR_BOT - TASKBAR_TOP),
            COLOR_TASKBAR,
        ).await?;


        Ok(())
    }

    async fn start_wsl(&self, conn: &MultiplexAddr) -> anyhow::Result<()> {
        log::info!("VM {}: Launching runner", self.name());
        let kb = self.get_keyboard_async().await?;
        kb.press_key(0x5B).await?; // VK_LWIN
        kb.press_key(0x52).await?; // R
        time::sleep(time::Duration::from_secs(3)).await;

        kb.release_key(0x5B).await?; // VK_LWIN
        kb.release_key(0x52).await?; // R

        self.wait_for_region(
            Vector2::new(WINRUN_X, WINRUN_Y),
            Vector2::new(1, 1),
            COLOR_WINRUN,
        ).await?;

        log::info!("VM {}: Launching debian", self.name());
        let [flag1, _] = get_flags()?;
        kb.type_text(format!(
            "debian -c \"echo 'RUNNING STUFF'; ~/run_shared.sh '{flag1}' '{}'; sleep 100\"",
            conn.bash_string(),
        )).await?;

        time::sleep(time::Duration::from_secs(3)).await;
        kb.press_key(0xD).await?; // VK_RETURN
        kb.stop().await?;

        log::info!("VM {}: Waiting for terminal", self.name());
        self.wait_for_region(
            Vector2::new(WINRUN_X, WINRUN_Y),
            Vector2::new(1, 1),
            COLOR_TERM,
        ).await?;

        Ok(())
    }
}

/*
fn save_screenshot(vssd_path: &str, file: &str, width: i16, height: i16) -> anyhow::Result<()> {
    let idata = snapshot(vssd_path, width, height)?;
    if let Some(idata) = idata {
        let idata: Vec<_> = idata.into_iter().flat_map(|mut v| {
            v = v * 256.0;
            [v.x as u8, v.y as u8, v.z as u8]
        }).collect();
        let file = std::fs::File::create(file)?;
        let mut img = png::Encoder::new(file, width.try_into()?, height.try_into()?);
        img.set_color(png::ColorType::Rgb);
        img.set_depth(png::BitDepth::Eight);
        let mut writer = img.write_header()?;
        writer.write_image_data(&idata)?;
        writer.finish()?;
    }
    Ok(())
}
*/

fn region_color(
    vssd_path: &str,
    width: i16,
    height: i16,
    top: Vector2<usize>,
    size: Vector2<usize>,
) -> anyhow::Result<Option<Vector3<f32>>> {
    let data = snapshot(&vssd_path, width, height)?;
    Ok(if let Some(pixels) = data {
        let mut sum = Vector3::zero();
        let mut cnt = 0;
        for x in top.x..(top.x + size.x) {
            for y in top.y..(top.y + size.y) {
                sum += pixels[y * width as usize + x];
                cnt += 1;
            }
        }
        Some(sum / cnt as f32)
    } else {
        None
    })
}

fn color_matches(
    actual_color: Option<Vector3<f32>>,
    target_color_set: &[Vector3<f32>],
) -> bool {
    let Some(color) = actual_color else {
        return false;
    };
    for target_color in target_color_set {
        if target_color.distance2(color) < 0.0001 {
            return true;
        }
    }
    false
}

async fn client_main(
    client: &mut net::TcpStream,
    caddr: SocketAddr,
    vhd_src: &str,
) -> anyhow::Result<()> {
    let (read, write) = client.split();
    let mut client = RW::new(io::BufReader::new(read), io::BufWriter::new(write));

    // Client authentication (PoW + get flag from pt 1). If this fails or
    // times out in 1 min we just exit here.
    let timeout = time::Instant::now() + time::Duration::from_secs(60);
    let is_admin = tokio::select! {
        auth_res = client_auth(&mut client) => {
            match auth_res? {
                None => return Ok(()),
                Some(is_admin) => is_admin,
            }
        }
        _ = wait_for_interrupt() => {
            log::info!("{caddr}: Interrupted while client auth!");
            return Ok(());
        }
        _ = time::sleep_until(timeout) => {
            log::info!("{caddr}: Timeout!");
            return Ok(());
        }
    };
    log::info!("{caddr}: Authenticated! is_admin = {is_admin}");

    // Check number of instances. Note that the "usage" of this is RAII
    let _inst = if is_admin {
        // Admin flag overrides instance counting
        None
    } else {
        match instances::InstanceAllocator::get() {
            Some(inst) => Some(inst),
            None => {
                client
                    .send("Too many instances running at the same time. Try again later.\n")
                    .await?;
                log::info!("{caddr}: Killed because too many sessions");
                return Ok(());
            }
        }
    };

    client
        .send("Partitioning new instance. This can take a few minutes. Please wait...\n")
        .await?;
    let mut vm_name = String::new();
    while vm_name.is_empty() || fs::try_exists(&vm_name).await? {
        let a = random_word::gen(random_word::Lang::En);
        let b = random_word::gen(random_word::Lang::En);
        let c = random_word::gen(random_word::Lang::En);
        vm_name = format!("{a}_{b}_{c}");
    }
    log::info!("{caddr}: Partitioning new instance: {vm_name}");

    let vm_ctx = format!("VM {vm_name}");
    let (key, vm) = partition_vm(vm_name, vhd_src, is_admin).await?;
    try_finally(
        async {
            log::info!("{vm_ctx}: Starting VM...");
            client
                .send("Partition complete! Starting up VM...\n")
                .await?;
            vm.start().await?;

            log::info!("{vm_ctx}: Waiting for VM to start up...");
            let timeout = time::Instant::now() + time::Duration::from_secs(600);
            let ctx = format!("VM {}", vm.name());
            let startup_task = async {
                vm.wait_for_region_set(
                    Vector2::new(LOGIN_X, LOGIN_Y),
                    Vector2::new(LOGIN_SZ, LOGIN_SZ),
                    vec![COLOR_LOGIN, COLOR_LOGIN2],
                ).await?;

                log::info!("{vm_ctx}: Inputing credentials");
                vm.input_credentials("user").await?;

                log::info!("{vm_ctx}: Opening terminal and running payload");
                VM_SESS_MGR.connect_server_peer(&key).await?;

                anyhow::Ok(())
            }
            .interruptable(&ctx, "waiting for VM startup")
            .timed(timeout);

            // This is to ensure that we don't try to spend more resources if the
            // user decides to DC from a connection
            tokio::select! {
                res = startup_task => { res }
                res = client.wait_for_eof() => { res? }
            }.ok_or_else(|| anyhow::anyhow!("Timeout while starting VM"))???;

            if is_admin {
                log::info!("{vm_ctx}: Ready for multi-connect instance");
                loop {
                    client
                        .send("Enter 'done' or close this connection to stop VM")
                        .await?;
                    let line = client
                        .recvline()
                        .interruptable(&vm_ctx, "waiting for client line")
                        .await??;
                    if line == "done" {
                        log::info!("{vm_ctx}: Disconnecting multi-connect instance!");
                        break;
                    }
                }
                VM_SESS_MGR.unregister(&key).await?;
            } else {
                log::info!("{vm_ctx}: Reading for single-connect instance!");
                connect_vm(&key, caddr, client).await?;
            }

            Ok(())
        },
        |is_success| {
            let vm_ctx = vm_ctx.clone();
            async move {
                match if is_success {
                    Ok(())
                } else {
                    log::info!("{vm_ctx}: Performing cleanup");
                    VM_SESS_MGR.unregister(&key).await
                } {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("{vm_ctx}: Unable to cleanup completely: {e}\n{}", e.backtrace())
                    }
                }
                Ok(())
            }
        },
    )
    .await
}

async fn connect_vm<R, W>(
    key: &u128,
    caddr: SocketAddr,
    mut client: RW<R, W>,
) -> Result<(), anyhow::Error>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut vm_conn = VM_SESS_MGR.connect_client_peer(key).await?;
    let mut buffer = vec![0u8; 0x1000];
    let mut buffer2 = vec![0u8; 0x1000];

    let timeout = time::Instant::now() + time::Duration::from_secs(300);
    client
        .send("Connected to VM! You have 300 seconds left.\n")
        .await?;
    loop {
        let (read, is_vm_to_client) = tokio::select! {
            vm_bytes = vm_conn.read(&mut buffer) => {
                (vm_bytes?, true)
            }
            client_bytes = client.read.read(&mut buffer2) => {
                (client_bytes?, false)
            }
            _ = time::sleep_until(timeout) => {
                log::info!("{caddr}: Timeout!");
                return Ok(());
            }
            _ = wait_for_interrupt() => {
                log::info!("{caddr}: Interrupted!");
                return Ok(());
            }
        };

        if is_vm_to_client {
            if read == 0 {
                client.write.shutdown().await?;
            } else {
                log::debug!(
                    "VM wrote: {}\n  {buffer:?}",
                    String::from_utf8_lossy(&buffer),
                );
                client.write.write(&buffer[0..read]).await?;
            }
        } else {
            if read == 0 {
                vm_conn.shutdown().await?;
            } else {
                log::debug!(
                    "Client wrote: {}\n  {buffer:?}",
                    String::from_utf8_lossy(&buffer),
                );
                vm_conn.write(&buffer2[0..read]).await?;
            }
        }
    }
}

async fn shared_main(
    client: &mut net::TcpStream,
    caddr: SocketAddr,
    key: &u128,
) -> anyhow::Result<()> {
    let (read, write) = client.split();
    let client = RW::new(io::BufReader::new(read), io::BufWriter::new(write));
    connect_vm(key, caddr, client).await?;
    Ok(())
}

#[derive(Default)]
struct SharedSockets {
    socks: BTreeMap<u128, net::TcpListener>,
}

impl SharedSockets {
    fn accept(&self) -> SharedSocketsAccept {
        SharedSocketsAccept(self)
    }

    async fn update(&mut self) -> anyhow::Result<()> {
        let shared = VM_SESS_MGR.shared_vms().await;
        let our_shared: BTreeSet<u128> = self.socks.keys().copied().collect();

        // Clean up any shared sessions that have been unregistered/terminated
        for our_key in &our_shared {
            if !shared.contains(our_key) {
                self.socks.remove(our_key);
            }
        }

        // Bind any new sockets that we recently registered
        for their_key in shared {
            if our_shared.contains(&their_key) {
                continue;
            }

            let list = net::TcpListener::bind(("0.0.0.0", 0)).await?;
            self.socks.insert(their_key, list);
        }
        Ok(())
    }
}

struct SharedSocketsAccept<'b>(&'b SharedSockets);

impl Future for SharedSocketsAccept<'_> {
    type Output = io::Result<(net::TcpStream, SocketAddr, u128)>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        for (&key, sock) in &self.0.socks {
            match sock.poll_accept(cx) {
                Poll::Ready(res) => return Poll::Ready(res.map(|(tcp, addr)| (tcp, addr, key))),
                Poll::Pending => (),
            }
        }
        Poll::Pending
    }
}

#[derive(bytemuck::Pod, bytemuck::Zeroable, Default, Clone, Copy)]
#[repr(C)]
struct MultiplexAddr {
    key: u128,
    port: usize,
    port_key: usize,
}

impl MultiplexAddr {
    fn bash_string(&self) -> String {
        let mut addr = String::with_capacity(size_of::<MultiplexAddr>() * 4);
        for b in bytemuck::bytes_of(self) {
            use std::fmt::Write;
            write!(addr, "\\x{b:02x}").unwrap();
        }
        addr
    }
}

async fn multiplex_main(mut client: net::TcpStream, caddr: &SocketAddr) -> anyhow::Result<()> {
    let timeout = time::Instant::now() + time::Duration::from_secs(60);
    let mut port_data = MultiplexAddr::default();
    client
        .read_exact(bytemuck::bytes_of_mut(&mut port_data))
        .timed(timeout)
        .await
        .ok_or_else(|| anyhow!("{caddr}: VM timeout while reading multiplex connection info"))??;

    let mut stream = Some(client);
    let res = VM_SESS_MGR.connect_peer(&port_data, &mut stream).await;
    if let Some(mut stream) = stream {
        stream.shutdown().await?;
    }
    res?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    hook_interrupt();

    let conn_sock = net::TcpListener::bind(("0.0.0.0", HOST_PORT_ENTRY)).await?;
    let mut shared = SharedSockets::default();

    let vhd_src = args()
        .nth(1)
        .ok_or_else(|| anyhow!("Expected positional argument for VHD"))?;

    match fs::try_exists(&vhd_src).await {
        Ok(true) => (),
        Ok(false) => {
            log::error!("{vhd_src}: File does not exist");
            return Ok(());
        }
        Err(e) => {
            log::error!("{vhd_src}: File does not exist: {e}");
            return Ok(());
        }
    }

    let ps = vmm::create_ps();

    log::info!("Initializing networking...");
    ps.run(
        r##"
$ErrorActionPreference = "Stop"
$switchName = "HostOnly"
$dhcpName = "DHCP-$switchName"
Write-Host "#[info] Creating vswitch"
if (-Not (Get-VMSwitch |? { $_.Name -Eq $switchName })) {
    New-VMSwitch -Name $switchName -SwitchType Internal
    #New-NetNat -Name $switchName -InternalIPInterfaceAddressPrefix "10.69.0.0/16"
}

Write-Host "#[info] Assigning IP Address for switch"
$ifIndex = (Get-NetAdapter |? { $_.Name -Like "*$switchName*" })[0].ifIndex
if (-Not (Get-NetIpAddress -InterfaceIndex 6 |? { $_.IPAddress -Eq "10.69.0.1"})) {
    New-NetIpAddress -IPAddress 10.69.0.1 -InterfaceIndex $ifIndex -PrefixLength 16
}

Write-Host "#[info] Configuring DHCP Server"
if (-Not (Get-DhcpServerV4Scope |? { $_.Name -Eq $dhcpName })) {
    Add-DhcpServerV4Scope -Name $dhcpName `
        -StartRange 10.69.0.50 `
        -EndRange 10.69.255.254 `
        -SubnetMask 255.255.0.0
}

Set-DhcpServerV4OptionValue -Router 10.69.0.1 -DnsServer 8.8.8.8

Write-Host "#[info] Restarting DHCP service"
Restart-service dhcpserver

Write-Host "#[info] Completed!"
exit 0
    "##,
    )
    .await?;

    log::info!("Waiting for connections!");
    log::info!(
        "Making VM instances in directory: {}",
        std::env::current_dir()?.as_os_str().to_string_lossy(),
    );

    let multiplex_sock = net::TcpListener::bind((HOST_IP, HOST_PORT_MULTIPLEX)).await?;
    let mut joins = JoinSet::new();
    loop {
        match shared.update().await {
            Ok(_) => {}
            Err(e) => log::error!("update_shared_sockets: {e}\n{}", e.backtrace()),
        }


        tokio::select! {
            val = multiplex_sock.accept() => {
                let (client, addr) = val?;
                joins.spawn(async move {
                    match multiplex_main(client, &addr).await {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("multiplex_main({addr}): {e}\n{}", e.backtrace());
                        }
                    }
                });
            }
            val = conn_sock.accept() => {
                let vhd_src = vhd_src.clone();
                let (mut client, addr) = val?;
                log::info!("Connected client: {addr}");
                joins.spawn(async move {
                    match client_main(&mut client, addr, &vhd_src).await {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("client_main({addr}): {e}\n{}", e.backtrace());
                            let _ = client.write(format!(
                                "Unexpected error occurred, please see admin: {e}"
                            ).as_bytes()).await;
                            let _ = client.flush().await;
                        }
                    }
                });
            }
            val = shared.accept() => {
                let (mut client, addr, key) = val?;
                joins.spawn(async move {
                    log::info!("Connected shared vm: {addr}");
                    match shared_main(&mut client, addr, &key).await {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("shared_main({addr}): {e}\n{}", e.backtrace());
                            let _ = client.write(format!(
                                "Unexpected error occurred, please see admin: {e}"
                            ).as_bytes()).await;
                            let _ = client.flush().await;
                        }
                    }
                });
            }
            _ = time::sleep(time::Duration::from_secs(1)) => {}
            _ = wait_for_interrupt() => {
                break;
            }
            _ = joins.join_next() => {
                continue;
            }
        }
    }

    while joins.join_next().await.is_some() {}

    Ok(())
}
