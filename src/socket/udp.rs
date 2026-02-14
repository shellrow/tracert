use super::SocketFamily;
use socket2::{Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketType {
    Dgram,
}

impl UdpSocketType {
    fn to_sock_type(&self) -> Type {
        match self {
            UdpSocketType::Dgram => Type::DGRAM,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpConfig {
    pub family: SocketFamily,
    pub socket_type: UdpSocketType,
    pub bind_addr: Option<SocketAddr>,
    pub ttl: Option<u32>,
    pub hop_limit: Option<u32>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
}

impl UdpConfig {
    pub fn new(family: SocketFamily) -> Self {
        Self {
            family,
            socket_type: UdpSocketType::Dgram,
            bind_addr: None,
            ttl: None,
            hop_limit: None,
            read_timeout: None,
            write_timeout: None,
        }
    }
}

#[derive(Debug)]
pub struct AsyncUdpSocket {
    inner: UdpSocket,
}

impl AsyncUdpSocket {
    pub fn from_config(config: &UdpConfig) -> io::Result<Self> {
        let socket = Socket::new(
            config.family.to_domain(),
            config.socket_type.to_sock_type(),
            Some(Protocol::UDP),
        )?;
        socket.set_nonblocking(true)?;

        if let Some(ttl) = config.ttl {
            socket.set_ttl(ttl)?;
        }
        if let Some(hop_limit) = config.hop_limit {
            socket.set_unicast_hops_v6(hop_limit)?;
        }
        if let Some(timeout) = config.read_timeout {
            socket.set_read_timeout(Some(timeout))?;
        }
        if let Some(timeout) = config.write_timeout {
            socket.set_write_timeout(Some(timeout))?;
        }
        if let Some(bind_addr) = config.bind_addr {
            socket.bind(&bind_addr.into())?;
        }

        #[cfg(windows)]
        let std_socket = unsafe {
            use std::os::windows::io::{FromRawSocket, IntoRawSocket};
            StdUdpSocket::from_raw_socket(socket.into_raw_socket())
        };
        #[cfg(unix)]
        let std_socket = unsafe {
            use std::os::fd::{FromRawFd, IntoRawFd};
            StdUdpSocket::from_raw_fd(socket.into_raw_fd())
        };

        Ok(Self {
            inner: UdpSocket::from_std(std_socket)?,
        })
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, target).await
    }
}
