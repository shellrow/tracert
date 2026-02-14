use super::SocketFamily;
use socket2::{Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IcmpSocketType {
    Dgram,
    Raw,
}

impl IcmpSocketType {
    fn to_sock_type(&self) -> Type {
        match self {
            IcmpSocketType::Dgram => Type::DGRAM,
            IcmpSocketType::Raw => Type::RAW,
        }
    }

    fn fallback(&self) -> Type {
        match self {
            IcmpSocketType::Dgram => Type::RAW,
            IcmpSocketType::Raw => Type::DGRAM,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IcmpConfig {
    pub family: SocketFamily,
    pub bind: Option<SocketAddr>,
    pub ttl: Option<u32>,
    pub hop_limit: Option<u32>,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub sock_type_hint: IcmpSocketType,
}

impl IcmpConfig {
    pub fn new(family: SocketFamily) -> Self {
        Self {
            family,
            bind: None,
            ttl: None,
            hop_limit: None,
            read_timeout: None,
            write_timeout: None,
            sock_type_hint: IcmpSocketType::Dgram,
        }
    }
}

#[derive(Debug)]
pub struct AsyncIcmpSocket {
    inner: UdpSocket,
}

impl AsyncIcmpSocket {
    pub async fn new(config: &IcmpConfig) -> io::Result<Self> {
        let proto = if config.family.is_v4() {
            Some(Protocol::ICMPV4)
        } else {
            Some(Protocol::ICMPV6)
        };

        let socket = match Socket::new(
            config.family.to_domain(),
            config.sock_type_hint.to_sock_type(),
            proto,
        ) {
            Ok(sock) => sock,
            Err(_) => Socket::new(
                config.family.to_domain(),
                config.sock_type_hint.fallback(),
                proto,
            )?,
        };

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
        if let Some(bind) = config.bind {
            socket.bind(&bind.into())?;
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

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }
}
