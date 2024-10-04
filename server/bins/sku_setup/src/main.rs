#![feature(once_cell_try)]
#![feature(array_try_map)]

use anyhow::anyhow;
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet}, env::args, future::Future, mem::swap, net::SocketAddr, process::exit, sync::{
        atomic::{AtomicBool, Ordering}, Arc, OnceLock
    }, task::Poll,
    thread,
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net, signal,
    sync::{Mutex, Notify},
    task::JoinSet,
    time::{self, Instant},
};
use vmm::{PSBool, PSState, StartAction, StopAction};

// 20000 diff ~ 8sec
const DIFFICULTY: u32 = 20;

const HOST_IP: &str = "10.69.0.1";
const HOST_PORT_MULTIPLEX: u16 = 31337;
const HOST_PORT_ENTRY: u16 = 20000;

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

struct RW<R: AsyncBufReadExt, W: AsyncWriteExt> {
    read: R,
    write: W,
    buff: String,
}

impl<R: AsyncBufReadExt + Unpin, W: AsyncWriteExt + Unpin> RW<R, W> {
    fn new(read: R, write: W) -> Self {
        RW {
            read,
            write,
            buff: String::new(),
        }
    }

    async fn send(&mut self, data: &str) -> anyhow::Result<()> {
        self.write.write(data.as_bytes()).await?;
        self.write.flush().await?;
        Ok(())
    }

    async fn recvline(&mut self) -> anyhow::Result<&str> {
        self.buff.clear();
        self.read.read_line(&mut self.buff).await?;
        Ok(self.buff.trim_end_matches(|c| c == '\n' || c == '\r'))
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
        tokio::spawn(async move {
            spawn_server(&vm, &mpa)
        }).await??;
        drop(sessions);

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
            log::info!("{name}: Copying base files");
            fs::create_dir(&name).await?;
            fs::copy(&vhd_src, &vhd_path).await?;
            if interrupted() {
                anyhow::bail!("{name}: Interrupted while copying files!");
            }

            log::info!("{name}: Registering VM");
            let key = VM_SESS_MGR.register_new(shared).await;
            log::info!("{name}: VM {name} -> 0x{key:032x}");

            *created_key.lock().await = Some(key);

            log::info!("{name}: Creating VM...");
            let vm = vmm::VmBuilder::default()
                .backing_path(name.clone())
                .name(name.clone())
                .use_gen2()
                .memory_startup_bytes("1GB".into())
                .existing_vhd(vhd_path)
                .path(format!("{name}/vm"))
                .boot_device(vmm::BootDevice::VHD)
                .build()
                .interruptable(&name, "creating VM")
                .await??;

            VM_SESS_MGR.associate_vm(&key, vm.clone()).await;

            log::info!("{name}: Configuring VM...");
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

            log::info!("{name}: Configuration completed!");
            Ok((key, vm))
        },
        |is_success| {
            let name = name.clone();
            let created_key = created_key.clone();
            async move {
                if !is_success {
                    log::warn!("{name}: Performing cleanup for VM due to error...");
                    let res = if let Some(key) = &*created_key.lock().await {
                        log::info!("{name}: ...by unregistering VM");
                        VM_SESS_MGR.unregister(key).await
                    } else {
                        log::info!("{name}: ...by removing the directory");
                        fs::remove_dir_all(&name).await.map_err(|e| e.into())
                    };

                    match res {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!("Unable to clean VM for {name}: {e}\n{}", e.backtrace())
                        }
                    }
                }
                Ok(())
            }
        },
    )
    .await
}

async fn try_finally<T, E, F>(
    action: impl Future<Output = Result<T, E>>,
    finally_case: impl Fn(bool) -> F,
) -> Result<T, E>
where
    F: Future<Output = Result<(), E>>,
{
    let res = action.await;
    finally_case(res.is_ok()).await?;
    res
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

fn snapshot(vssd_path: &str) -> anyhow::Result<Vec<u8>> {
    let vsm = wmi_ext::VirtualSystemManagementService::singleton()?;
    let vssd = wmi_ext::VirtualSystemSettingData::new(vssd_path.into());
    vsm.get_virtual_system_thumbnail_image(&vssd, 8, 8)
}

fn spawn_server(vm: &vmm::Vm, conn: &MultiplexAddr) -> anyhow::Result<()> {
    let keyboard = vm.try_get_keyboard()?;

    keyboard.type_key(0x5B)?; // VK_LWIN
    thread::sleep(time::Duration::from_secs_f32(0.1));

    keyboard.type_text("debian".into())?;
    thread::sleep(time::Duration::from_secs_f32(0.5));

    keyboard.type_key(0xD)?; // VK_RETURN
    thread::sleep(time::Duration::from_secs(2));

    let [flag1, _] = get_flags()?;
    keyboard.type_text(format!(
        "./run_shared.sh '{flag1}' '{}'\n",
        conn.bash_string(),
    ))?;

    Ok(())
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

    let (key, vm) = partition_vm(vm_name, vhd_src, is_admin).await?;
    try_finally(
        async {
            log::info!("{caddr}: Starting VM...");
            client
                .send("Partition complete! Starting up VM...\n")
                .await?;
            vm.start().await?;

            log::info!("{caddr}: Waiting for VM to start up...");
            let timeout = time::Instant::now() + time::Duration::from_secs(300);

            let vssd_path = vm
                .get_vssd()?
                .ok_or_else(|| anyhow!("VM does not have system settings associated"))?
                .wmi_path;
            loop {
                let data = snapshot(&vssd_path)?;
                println!("{data:?}");

                let len = u32::from_ne_bytes(data[0..4].try_into().unwrap()) as usize;
                println!("{:?}", &data[4..4+len]);
                if data[0] == 0x13 {
                    break;
                }

                time::sleep(time::Duration::from_secs(1))
                    .timed(timeout)
                    .interruptable(&caddr, "waiting for VM startup")
                    .await?
                    .ok_or_else(|| anyhow!("{caddr}: VM timeout while waiting for VM startup"))?;
            }

            log::info!("{caddr}: Inputing credentials");
            std::future::pending::<()>().await;

            log::info!("{caddr}: Opening terminal and running payload");
            VM_SESS_MGR.connect_server_peer(&key).await?;

            if is_admin {
                log::info!("{caddr}: Ready for multi-connect instance");
                loop {
                    client
                        .send("Enter 'done' or close this connection to stop VM")
                        .await?;
                    let line = client
                        .recvline()
                        .interruptable(&caddr, "waiting for client line")
                        .await??;
                    if line == "done" {
                        log::info!("{caddr}: Disconnecting multi-connect instance!");
                        break;
                    }
                }
                VM_SESS_MGR.unregister(&key).await?;
            } else {
                log::info!("{caddr}: Reading for single-connect instance!");
                connect_vm(timeout, &key, caddr, client).await?;
            }

            Ok(())
        },
        |is_success| async move {
            if !is_success {
                log::info!("{caddr}: Performing cleanup");
                VM_SESS_MGR.unregister(&key).await?;
            }
            Ok(())
        },
    )
    .await
}

async fn connect_vm<R, W>(
    timeout: time::Instant,
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
    let timeout = time::Instant::now() + time::Duration::from_secs(300);
    connect_vm(timeout, key, caddr, client).await?;
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
