#![feature(once_cell_try)]
#![feature(array_try_map)]
#![feature(slice_split_once)]

use anyhow::anyhow;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net,
    task::JoinSet,
    time,
};

use utils::FutureExt;

const HOST_IP: &str = "10.69.0.1";
const HOST_PORT_MULTIPLEX: u16 = 31337;
const HOST_PORT_ENTRY: u16 = 20000;

mod sess;
mod utils;

async fn connect_vm(
    key: &u128,
    caddr: SocketAddr,
    client: &mut net::TcpStream,
) -> Result<(), anyhow::Error> {
    let mut vm_conn = sess::VM_SESS_MGR.connect_client_peer(key).await?;
    let mut buffer = vec![0u8; 0x1000];
    let mut buffer2 = vec![0u8; 0x1000];

    let timeout = time::Instant::now() + time::Duration::from_secs(300);
    client
        .write_all(b"Connected to VM! You have 300 seconds left.\n")
        .await?;
    loop {
        let (read, is_vm_to_client) = tokio::select! {
            vm_bytes = vm_conn.read(&mut buffer) => {
                (vm_bytes?, true)
            }
            client_bytes = client.read(&mut buffer2) => {
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
                client.shutdown().await?;
            } else {
                log::debug!(
                    "VM wrote: {}\n  {buffer:?}",
                    String::from_utf8_lossy(&buffer),
                );
                client.write_all(&buffer[0..read]).await?;
            }
        } else {
            if read == 0 {
                vm_conn.shutdown().await?;
            } else {
                log::debug!(
                    "Client wrote: {}\n  {buffer:?}",
                    String::from_utf8_lossy(&buffer),
                );
                vm_conn.write_all(&buffer2[0..read]).await?;
            }
        }
    }
}

async fn shared_main(
    client: &mut net::TcpStream,
    caddr: SocketAddr,
    key: &u128,
) -> anyhow::Result<()> {
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
    env_logger::init();
    utils::init();

    let conn_sock = net::TcpListener::bind(("0.0.0.0", HOST_PORT_ENTRY)).await?;

    log::info!("Connecting to VM. Make sure that the VM is on a network interface where our IP is {HOST_IP}.");
    let multiplex_sock = net::TcpListener::bind((HOST_IP, HOST_PORT_MULTIPLEX)).await?;
    let key = sess::VM_SESS_MGR.register_new().await;
    sess::VM_SESS_MGR.connect_server_peer(&key).await?;

    log::info!("Waiting for connections!");
    let mut joins = JoinSet::new();
    loop {
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
                let (mut client, addr) = val?;
                joins.spawn(async move {
                    log::info!("Connected shared vm: {addr}");
                    match shared_main(&mut client, addr, &0).await {
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
