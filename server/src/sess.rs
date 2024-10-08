use crate::vmm;
use rand::Rng;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::swap,
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
    port: usize,
    port_key: usize,
}

impl MultiplexAddr {
    pub fn bash_string(&self) -> String {
        let mut addr = String::with_capacity(size_of::<MultiplexAddr>() * 4);
        for b in bytemuck::bytes_of(self) {
            use std::fmt::Write;
            write!(addr, "\\x{b:02x}").unwrap();
        }
        addr
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

pub struct VmSessionsMgr {
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

pub static VM_SESS_MGR: VmSessionsMgr = VmSessionsMgr::new();