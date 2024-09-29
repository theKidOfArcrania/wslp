#![feature(once_cell_try)]
use anyhow::anyhow;
use std::{
    collections::{BTreeMap, BTreeSet},
    env::args,
    future::Future,
    net::{IpAddr, SocketAddr},
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::Poll,
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net, signal,
    sync::{Mutex, Notify},
    task::JoinSet,
    time,
};
use vmm::{PSBool, PSState, StartAction, StopAction};

// 20000 diff ~ 8sec
const DIFFICULTY: u32 = 20;

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
    /*
    pub async fn unregister(&self, key: &u128) -> anyhow::Result<()> {
        let sess = self.sessions.lock().await.remove(&key);
        if let Some(vm) = sess.and_then(|sess| sess.vm) {
            vm.cleanup().await?;
        }

        self.shared.lock().await.remove(&key);
        Ok(())
    }
    */


trait FutureExt<T> {
    async fn interruptable(
        self,
        ctx: &(dyn std::fmt::Display + Sync),
        action: &str,
    ) -> anyhow::Result<T>;
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
}

async fn partition_vm(
    name: String,
    vhd_src: &str,
    shared: bool,
) -> anyhow::Result<vmm::Vm> {
    if !vhd_src.ends_with(".vhdx") {
        anyhow::bail!("VHD should end in .vhdx");
    }
    let vhd_path = format!("{name}/disk.vhdx");

    let created_vm = Arc::new(Mutex::new(None));
    try_finally(
        async {
            log::info!("{name}: Copying base files");
            fs::create_dir(&name).await?;
            fs::copy(&vhd_src, &vhd_path).await?;
            if interrupted() {
                anyhow::bail!("{name}: Interrupted while copying files!");
            }

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

            *created_vm.lock().await = Some(vm.clone());

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
            Ok(vm)
        },
        |is_success| {
            let name = name.clone();
            let created_vm = created_vm.clone();
            async move {
                if !is_success {
                    log::info!("{name}: Performing cleanup for VM...");
                    let res = if let Some(vm) = created_vm.lock().await.take() {
                        log::info!("{name}: ...by cleaning up VM");
                        vm.cleanup().await
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
    let flag1 = fs::read_to_string("flag1.txt").await?;
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

    let vm = partition_vm(vm_name, vhd_src, is_admin).await?;
    let vm2 = vm.clone();
    try_finally(
        async {
            log::info!("{caddr}: Starting VM...");
            client
                .send("Partition complete! Starting up VM...\n")
                .await?;
            vm.start().await?;

            log::info!("{caddr}: Waiting for handshake...");
            let timeout = time::Instant::now() + time::Duration::from_secs(300);
            /*
            let addr = VM_SESS_MGR
                .wait_for_ip(&key)
                .interruptable(&caddr, "waiting for handshake")
                .await?
                .ok_or_else(|| anyhow!("VM {key:032x} is not initialized yet"))?;
            */

            if is_admin {
                log::info!("{caddr}: Ready for multi-connect instance");
                loop {
                    client
                        .send("Enter 'done' or close this connection to stop VM")
                        .await?;
                    let line = client
                        .recvline()
                        .interruptable(&caddr, "waiting for clent line")
                        .await??;
                    if line == "done" {
                        log::info!("{caddr}: Disconnecting multi-connect instance!");
                        break;
                    }
                }
            } else {
                log::info!("{caddr}: Reading for single-connect instance!");
                connect_vm(timeout, addr, caddr, client).await?;
            }

            Ok(())
        },
        |is_success| async move {
            if !is_success {
                vm2.cleanup().await?;
            }
            Ok(())
        },
    )
    .await
}

async fn connect_vm<R, W>(
    timeout: time::Instant,
    addr: IpAddr,
    caddr: SocketAddr,
    mut client: RW<R, W>,
) -> Result<(), anyhow::Error>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut vm_conn = net::TcpSocket::new_v4()?
        .connect(SocketAddr::new(addr, 1337))
        .interruptable(&caddr, "connecting to VM")
        .await??;
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
    let vm_session = VM_SESS_MGR
        .get_vm_session(key)
        .await
        .ok_or_else(|| anyhow!("Unable to get vm {key:032x}"))?;
    let vm_addr = vm_session
        .ip
        .ok_or_else(|| anyhow!("VM {key:032x} is not initialized yet"))?;
    let (read, write) = client.split();
    let client = RW::new(io::BufReader::new(read), io::BufWriter::new(write));

    match &vm_session.vm {
        None => {
            log::info!("{caddr}: Connected to shared VM: 0x{:032x}", key);
        }
        Some(vm) => {
            log::info!("{caddr}: Connected to shared VM: {}", vm.name());
        }
    }
    let timeout = time::Instant::now() + time::Duration::from_secs(300);
    connect_vm(timeout, vm_addr, caddr, client).await?;
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

            let maddr = VM_SESS_MGR
                .get_vm_session(&their_key)
                .await
                .and_then(|vm_sess| vm_sess.ip);
            if let Some(addr) = maddr {
                let saddr = SocketAddr::new(addr, 0);
                let list = net::TcpListener::bind(saddr).await?;
                self.socks.insert(their_key, list);
            }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    hook_interrupt();

    let conn_sock = net::TcpListener::bind(("0.0.0.0", 20000)).await?;
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
Set-NetIpAddress -IPAddress 10.69.0.1 -InterfaceIndex $ifIndex -PrefixLength 16

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

    let mut joins = JoinSet::new();
    loop {
        match shared.update().await {
            Ok(_) => {}
            Err(e) => log::error!("update_shared_sockets: {e}\n{}", e.backtrace()),
        }

        tokio::select! {
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
