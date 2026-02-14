use super::SocketFamily;
use socket2::{Protocol, Socket, Type};
use std::io;
use std::net::{SocketAddr, TcpStream as StdTcpStream};
use std::time::Duration;
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct TcpConfig {
    pub family: SocketFamily,
    pub ttl: Option<u32>,
    pub hop_limit: Option<u32>,
    pub nodelay: Option<bool>,
}

impl TcpConfig {
    pub fn new(family: SocketFamily) -> Self {
        Self {
            family,
            ttl: None,
            hop_limit: None,
            nodelay: None,
        }
    }
}

#[derive(Debug)]
pub struct AsyncTcpSocket {
    socket: Socket,
}

impl AsyncTcpSocket {
    pub fn from_config(config: &TcpConfig) -> io::Result<Self> {
        let socket = Socket::new(config.family.to_domain(), Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;

        if let Some(ttl) = config.ttl {
            socket.set_ttl(ttl)?;
        }
        if let Some(hop_limit) = config.hop_limit {
            socket.set_unicast_hops_v6(hop_limit)?;
        }
        if let Some(nodelay) = config.nodelay {
            socket.set_nodelay(nodelay)?;
        }

        Ok(Self { socket })
    }

    pub async fn connect(self, target: SocketAddr) -> io::Result<TcpStream> {
        match self.socket.connect(&target.into()) {
            Ok(_) => {
                let std_stream: StdTcpStream = self.socket.into();
                TcpStream::from_std(std_stream)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let std_stream: StdTcpStream = self.socket.into();
                let stream = TcpStream::from_std(std_stream)?;
                stream.writable().await?;
                if let Some(err) = stream.take_error()? {
                    Err(err)
                } else {
                    Ok(stream)
                }
            }
            Err(e) => Err(e),
        }
    }

    pub async fn connect_timeout(
        self,
        target: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        match tokio::time::timeout(timeout, self.connect(target)).await {
            Ok(result) => result,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "connection timed out",
            )),
        }
    }
}
