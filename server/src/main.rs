#![feature(once_cell_try)]
#![feature(array_try_map)]
#![feature(slice_split_once)]

use anyhow::anyhow;
use clap::Parser;
use std::{
    collections::{BTreeMap, BTreeSet},
    env::set_current_dir,
    future::Future,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    task::Poll,
};
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt},
    net,
    sync::Mutex,
    task::JoinSet,
    time,
};

use utils::FutureExt;
use vmm::{PSBool, PSState, StartAction, StopAction};

const HOST_IP: &str = "10.69.0.1";
const HOST_PORT_MULTIPLEX: u16 = 31337;
const HOST_PORT_ENTRY: u16 = 20000;

mod instances;
mod sess;
mod utils;
mod vmm;
mod vmm_async;
pub mod wmi_ext;

#[derive(Parser)]
struct Arguments {
    /// Don't copy the vhdx file.
    #[clap(long)]
    no_copy: bool,

    #[clap(long, short = 'f', required = true)]
    /// The vhdx file corresponding to the SKU that should be used for each
    /// VM instance
    vhdx_file: String,

    /// The PoW difficulty that should be used for starting up each VM. Defaults
    /// to a difficulty of 20000
    // 20000 diff ~ 8sec
    #[clap(long, short, default_value_t = 20000)]
    difficulty: u32,

    /// The directory path to dump all VMs in. By default this will be the
    /// current directory. All the expected flag files should be located in this
    /// directory.
    vm_path: Option<String>,
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
        let shared = sess::VM_SESS_MGR.shared_vms().await;
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

async fn partition_vm(
    name: String,
    vhd_src: &Path,
    shared: bool,
    no_copy: bool,
) -> anyhow::Result<(u128, vmm::Vm)> {
    if !vhd_src.ends_with(".vhdx") {
        anyhow::bail!("VHD should end in .vhdx");
    }
    let vhd_path = format!("{name}/disk.vhdx");

    let created_key = Arc::new(Mutex::new(None));
    utils::try_finally(
        async {
            fs::create_dir(&name).await?;
            let vhd_path = if no_copy {
                vhd_src
            } else {
                log::info!("VM {name}: Copying base files");
                fs::copy(&vhd_src, &vhd_path).await?;
                if utils::interrupted() {
                    anyhow::bail!("VM {name}: Interrupted while copying files!");
                }
                vhd_path.as_ref()
            };

            let key = sess::VM_SESS_MGR.register_new(shared).await;
            log::info!("VM {name}: Registered VM -> 0x{key:032x}");

            *created_key.lock().await = Some(key);

            log::info!("VM {name}: Creating VM...");
            let vm = vmm::VmBuilder::default()
                .backing_path(name.clone())
                .name(name.clone())
                .use_gen2()
                .memory_startup_bytes("1GB".into())
                .existing_vhd(
                    vhd_path
                        .to_str()
                        .ok_or_else(|| anyhow!("VM {name}: not a valid VHD path"))?
                        .into(),
                )
                .path(format!("{name}/vm"))
                .boot_device(vmm::BootDevice::VHD)
                .build()
                .interruptable(&name, "creating VM")
                .await??;

            sess::VM_SESS_MGR.associate_vm(&key, vm.clone()).await;

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
                        sess::VM_SESS_MGR.unregister(key).await
                    } else {
                        log::info!("VM {name}: ...by removing the directory");
                        fs::remove_dir_all(&name).await.map_err(|e| e.into())
                    };

                    match res {
                        Ok(()) => {}
                        Err(e) => {
                            log::error!(
                                "VM {name}: Unable to cleanup completely: {e}\n{}",
                                e.backtrace()
                            )
                        }
                    }
                }
                Ok(())
            }
        },
    )
    .await
}

async fn client_auth<R, W>(
    difficulty: u32,
    client: &mut utils::RW<R, W>,
) -> anyhow::Result<Option<bool>>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // Call PoW
    let pow = kctf_pow::KctfPow::new();
    let chall = pow.generate_challenge(difficulty);
    let prompt = format!("./kctf-pow solve {}\n> ", chall.to_string(),);
    match chall.check(client.recvlineafter(&prompt).await?) {
        Ok(true) => {}
        _ => {
            client.send("Bad PoW response\n").await?;
            return Ok(None);
        }
    }

    // Check flag
    let flag1 = utils::get_flag1()?;
    let response = client.recvlineafter("Flag from part 1: ").await?;
    let is_admin = if response.trim() == flag1.trim() {
        false
    } else if response == "ADMIN_ADMIN!!!!_6G93ugsoi;jsjfaie" {
        client.send("Admin mode activated!\n").await?;
        true
    } else {
        client.send("Wrong flag\n").await?;
        return Ok(None);
    };

    Ok(Some(is_admin))
}

async fn client_main(
    difficulty: u32,
    client: &mut net::TcpStream,
    caddr: SocketAddr,
    vhd_src: &Path,
    no_copy: bool,
) -> anyhow::Result<()> {
    let (read, write) = client.split();
    let mut client = utils::RW::new(io::BufReader::new(read), io::BufWriter::new(write));

    // Client authentication (PoW + get flag from pt 1). If this fails or
    // times out in 1 min we just exit here.
    let timeout = time::Instant::now() + time::Duration::from_secs(60);
    let is_admin = tokio::select! {
        auth_res = client_auth(difficulty, &mut client) => {
            match auth_res? {
                None => return Ok(()),
                Some(is_admin) => is_admin,
            }
        }
        _ = utils::wait_for_interrupt() => {
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
    let (key, vm) = partition_vm(vm_name, vhd_src, is_admin, no_copy).await?;
    utils::try_finally(
        async {
            log::info!("{vm_ctx}: Starting VM...");
            client
                .send("Partition complete! Starting up VM...\n")
                .await?;
            vm.start().await?;

            let timeout = time::Instant::now() + time::Duration::from_secs(600);
            let startup_task = async {
                log::info!("{vm_ctx}: Waiting for VM to start up...");
                vm.wait_for_login().await?;

                log::info!("{vm_ctx}: Inputing credentials");
                vm.input_credentials("user").await?;

                log::info!("{vm_ctx}: Opening terminal and running payload");
                sess::VM_SESS_MGR.connect_server_peer(&key).await?;

                anyhow::Ok(())
            }
            .interruptable(&vm_ctx, "waiting for VM startup")
            .timed(timeout);

            // This is to ensure that we don't try to spend more resources if the
            // user decides to DC from a connection
            tokio::select! {
                res = startup_task => { res }
                res = client.wait_for_eof() => { res? }
            }
            .ok_or_else(|| anyhow::anyhow!("Timeout while starting VM"))???;

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
                sess::VM_SESS_MGR.unregister(&key).await?;
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
                    sess::VM_SESS_MGR.unregister(&key).await
                } {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!(
                            "{vm_ctx}: Unable to cleanup completely: {e}\n{}",
                            e.backtrace()
                        )
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
    mut client: utils::RW<R, W>,
) -> Result<(), anyhow::Error>
where
    R: AsyncBufReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut vm_conn = sess::VM_SESS_MGR.connect_client_peer(key).await?;
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
            _ = utils::wait_for_interrupt() => {
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
    let client = utils::RW::new(io::BufReader::new(read), io::BufWriter::new(write));
    connect_vm(key, caddr, client).await?;
    Ok(())
}

async fn multiplex_main(mut client: net::TcpStream, caddr: &SocketAddr) -> anyhow::Result<()> {
    let timeout = time::Instant::now() + time::Duration::from_secs(60);
    let mut port_data = sess::MultiplexAddr::default();
    client
        .read_exact(bytemuck::bytes_of_mut(&mut port_data))
        .timed(timeout)
        .await
        .ok_or_else(|| anyhow!("{caddr}: VM timeout while reading multiplex connection info"))??;

    let mut stream = Some(client);
    let res = sess::VM_SESS_MGR
        .connect_peer(&port_data, &mut stream)
        .await;
    if let Some(mut stream) = stream {
        stream.shutdown().await?;
    }
    res?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Arguments::parse();
    let vhd_name = args.vhdx_file.clone();
    let vhd_src = std::fs::canonicalize(args.vhdx_file)?;
    if let Some(vm_path) = args.vm_path {
        set_current_dir(vm_path)?;
    }

    env_logger::init();
    utils::init();

    let conn_sock = net::TcpListener::bind(("0.0.0.0", HOST_PORT_ENTRY)).await?;
    let mut shared = SharedSockets::default();

    match fs::try_exists(&vhd_src).await {
        Ok(true) => (),
        Ok(false) => {
            log::error!("{vhd_name}: File does not exist");
            return Ok(());
        }
        Err(e) => {
            log::error!("{vhd_name}: File does not exist: {e}");
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
if (-Not (Get-NetIpAddress -InterfaceIndex $ifIndex |? { $_.IPAddress -Eq "10.69.0.1"})) {
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
                    match client_main(args.difficulty, &mut client, addr, &vhd_src, args.no_copy).await {
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
            _ = utils::wait_for_interrupt() => {
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
