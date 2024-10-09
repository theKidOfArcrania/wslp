use rand::Rng;
use std::{
    collections::BTreeMap,
    mem::swap, sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::AsyncWriteExt,
    net,
    sync::{Mutex, Notify},
};

#[derive(bytemuck::Pod, bytemuck::Zeroable, Default, Clone, Copy)]
#[repr(C)]
pub struct MultiplexAddr {
    key: u128,
    port: u64,
    port_key: u64,
}

impl std::fmt::Display for MultiplexAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_low = self.key as u64;
        let key_high = (self.key >> 64) as u64;
        write!(
            f,
            "{key_low:016x}:{key_high:016x}:{:016x}:{:016x}",
            self.port, self.port_key
        )
    }
}

enum PeerState {
    Connecting(u64),
    PartialConnected(net::TcpStream),
    FullyConnected,
}

#[derive(Default)]
struct VmSession {
    server_peer: Option<net::TcpStream>,
    peers: Vec<PeerState>,
}

pub struct VmSessionsMgr {
    sessions: Mutex<BTreeMap<u128, VmSession>>,
    peer_notify: Notify,
    next_key: AtomicU64,
}

impl VmSessionsMgr {
    pub const fn new() -> Self {
        Self {
            sessions: Mutex::const_new(BTreeMap::new()),
            peer_notify: Notify::const_new(),
            next_key: AtomicU64::new(0),
        }
    }

    pub async fn register_new(&self) -> u128 {
        let key = self.next_key.fetch_add(1, Ordering::Relaxed) as u128;
        self.sessions.lock().await.insert(key, VmSession::default());
        key
    }

    pub async fn connect_server_peer(&self, key: &u128) -> anyhow::Result<()> {
        let mpa = self.open_peer(key).await?;

        let sessions = self.sessions.lock().await;
        if !sessions.contains_key(&key) {
            anyhow::bail!("VM 0x{key:032x} does not exist");
        };
        drop(sessions);

        println!("Run `/home/ctf/runner {mpa}` in the VM to connect");

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

        server.write_all(bytemuck::bytes_of(&mpa)).await?;
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
            port: sess.peers.len() as u64 - 1,
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

        let Some(peer) = sess
            .peers
            .get_mut(conn.port as usize)
            .filter(|peer| match peer {
                PeerState::Connecting(port_key) => conn.port_key == *port_key,
                _ => false,
            })
        else {
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

    pub async fn wait_for_peer(&self, key: &u128, port: u64) -> anyhow::Result<net::TcpStream> {
        log::info!("{key:032x}: Waiting for peer connection to port {port}");
        loop {
            let mut sessions = self.sessions.lock().await;
            let Some(sess) = sessions.get_mut(&key) else {
                anyhow::bail!("VM 0x{key:032x} does not exist");
            };

            let Some(peer) = sess.peers.get_mut(port as usize) else {
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

pub static VM_SESS_MGR: VmSessionsMgr = VmSessionsMgr::new();
