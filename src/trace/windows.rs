use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::cmp::min;
use std::time::{Duration, Instant};
use std::mem::{self, size_of, MaybeUninit};
use std::ptr;
use std::sync::Once;
use std::io;
use socket2::SockAddr;
use pnet_packet::Packet;
use pnet_packet::icmp::{IcmpTypes};
use winapi::ctypes::c_int;
use winapi::ctypes::c_long;
use winapi::shared::mstcpip::SIO_RCVALL;
use winapi::shared::ws2def::{AF_INET, AF_INET6, IPPROTO_IP};
use winapi::um::winsock2::{self as sock, u_long, SOCKET, SOCK_RAW, WSA_FLAG_NO_HANDLE_INHERIT, SOL_SOCKET, SO_RCVTIMEO};
use winapi::shared::minwindef::DWORD;
use winapi::um::winbase::{INFINITE};

use super::BASE_DST_PORT;
use super::node::{NodeType, Node};

//const BASE_DST_PORT: u16 = 33435;
const NO_INHERIT: c_int = 1 << ((size_of::<c_int>() * 8) - 1);
const MAX_BUF_LEN: usize = <c_int>::max_value() as usize;

#[allow(unused_macros)]
macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_test: path, $err_value: expr) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { sock::$fn($($arg, )*) };
        if $err_test(&res, &$err_value) {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

fn init_socket() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = UdpSocket::bind("127.0.0.1:34254");
    });
}

fn ioctlsocket(socket: SOCKET, cmd: c_long, payload: &mut u_long) -> io::Result<()> {
    syscall!(
        ioctlsocket(socket, cmd, payload),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

fn create_socket(family: c_int, mut ty: c_int, protocol: c_int) -> io::Result<SOCKET> {
    init_socket();
    let flags = if ty & NO_INHERIT != 0 {
        ty = ty & !NO_INHERIT;
        WSA_FLAG_NO_HANDLE_INHERIT
    } else {
        0
    };
    syscall!(
        WSASocketW(
            family,
            ty,
            protocol,
            ptr::null_mut(),
            0,
            sock::WSA_FLAG_OVERLAPPED | flags,
        ),
        PartialEq::eq,
        sock::INVALID_SOCKET
    )
}

fn bind(socket: SOCKET, addr: &SockAddr) -> io::Result<()> {
    syscall!(bind(socket, addr.as_ptr(), addr.len()), PartialEq::ne, 0).map(|_| ())
}

#[allow(dead_code)]
fn set_nonblocking(socket: SOCKET, nonblocking: bool) -> io::Result<()> {
    let mut nonblocking = nonblocking as u_long;
    ioctlsocket(socket, sock::FIONBIO, &mut nonblocking)
}

fn set_promiscuous(socket: SOCKET, promiscuous: bool) -> io::Result<()> {
    let mut promiscuous = promiscuous as u_long;
    ioctlsocket(socket, SIO_RCVALL as i32, &mut promiscuous)
}

unsafe fn setsockopt<T>(
    socket: SOCKET,
    level: c_int,
    optname: c_int,
    optval: T,
) -> io::Result<()> {
    syscall!(
        setsockopt(
            socket,
            level,
            optname,
            (&optval as *const T).cast(),
            mem::size_of::<T>() as c_int,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

fn into_ms(duration: Option<Duration>) -> DWORD {
    duration
        .map(|duration| min(duration.as_millis(), INFINITE as u128) as DWORD)
        .unwrap_or(0)
}

pub(crate) fn set_timeout_opt(
    fd: SOCKET,
    level: c_int,
    optname: c_int,
    duration: Option<Duration>,
) -> io::Result<()> {
    let duration = into_ms(duration);
    unsafe { setsockopt(fd, level, optname, duration) }
}

fn recv_from(
    socket: SOCKET,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    unsafe {
        SockAddr::init(|storage, addrlen| {
            let res = syscall!(
                recvfrom(
                    socket,
                    buf.as_mut_ptr().cast(),
                    min(buf.len(), MAX_BUF_LEN) as c_int,
                    flags,
                    storage.cast(),
                    addrlen,
                ),
                PartialEq::eq,
                sock::SOCKET_ERROR
            );
            match res {
                Ok(n) => Ok(n as usize),
                Err(ref err) if err.raw_os_error() == Some(sock::WSAESHUTDOWN as i32) => Ok(0),
                Err(err) => Err(err),
            }
        })
    }
}

pub fn trace_route(src_ip: IpAddr, dst_ip: IpAddr, max_hop: u8, receive_timeout: Duration) -> Result<Vec<Node>, String> {
    let mut result: Vec<Node> = vec![];
    let udp_socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("{}", e));
        },
    };
    let socket: SOCKET = 
    if src_ip.is_ipv4() {
        create_socket(AF_INET, SOCK_RAW, IPPROTO_IP).unwrap()
    }else if src_ip.is_ipv6(){
        create_socket(AF_INET6, SOCK_RAW, IPPROTO_IP).unwrap()
    }else{
        return Err(String::from("invalid source address"));
    };
    let socket_addr: SocketAddr = SocketAddr::new(src_ip, 0);
    //let socket_addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0);
    let sock_addr = SockAddr::from(socket_addr);
    bind(socket, &sock_addr).unwrap();
    //set_nonblocking(socket, true).unwrap();
    set_promiscuous(socket, true).unwrap();
    set_timeout_opt(socket, SOL_SOCKET, SO_RCVTIMEO, Some(receive_timeout)).unwrap();
    let mut end_trace: bool = false;
    for ttl in 1..max_hop {
        if end_trace {
            break;
        }
        match udp_socket.set_ttl(ttl as u32) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        let udp_buf = [0u8; 0];
        let dst: SocketAddr = SocketAddr::new(dst_ip, BASE_DST_PORT + ttl as u16);
        let send_time = Instant::now();
        let mut buf: Vec<u8> = vec![0; 512];
        let recv_buf = unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [MaybeUninit<u8>]) };
        match udp_socket.send_to(&udp_buf, dst) {
            Ok(_) => (),
            Err(e) => {
                return Err(format!("{}", e));
            },
        }
        loop {
            let elapsed_time = Instant::now().duration_since(send_time);
            if elapsed_time > receive_timeout {
                break;
            }
            match recv_from(socket, recv_buf, 0) {
                Ok((bytes_len, addr)) => {
                    let src_addr: IpAddr = addr.as_socket().unwrap_or(SocketAddr::new(src_ip, 0)).ip();
                    if src_ip == src_addr {
                        continue;
                    }
                    let recv_time = Instant::now().duration_since(send_time);
                    let recv_buf = unsafe { *(recv_buf as *mut [MaybeUninit<u8>] as *mut [u8; 512]) };
                    if let Some(packet) = pnet_packet::ipv4::Ipv4Packet::new(&recv_buf[0..bytes_len]){
                        let icmp_packet = pnet_packet::icmp::IcmpPacket::new(packet.payload());
                        if let Some(icmp) = icmp_packet {
                            let ip_addr: IpAddr = IpAddr::V4(packet.get_source());

                            //let host_name: String = dns_lookup::lookup_addr(&ip_addr).unwrap_or(ip_addr.to_string());
                            match icmp.get_icmp_type() {
                                IcmpTypes::TimeExceeded => {
                                    result.push(Node {
                                        ip_addr: ip_addr,
                                        host_name: String::new(),
                                        hop: ttl,
                                        node_type: if ttl == 1 {NodeType::DefaultGateway}else{NodeType::Relay},
                                        rtt: recv_time,
                                    });
                                    //println!("{} TimeExceeded {:?}", ttl, packet.get_source());
                                },
                                IcmpTypes::DestinationUnreachable => {
                                    result.push(Node {
                                        ip_addr: ip_addr,
                                        host_name: String::new(),
                                        hop: ttl,
                                        node_type: NodeType::Destination,
                                        rtt: recv_time,
                                    });
                                    //println!("{} DestinationUnreachable {:?}", ttl, packet.get_source());
                                    end_trace = true;
                                    break;
                                },
                                _ => {},
                            }
                        }
                    }
                },
                Err(_) => {},
            }
        }   
    }
    for node in &mut result {
        let host_name: String = dns_lookup::lookup_addr(&node.ip_addr).unwrap_or(node.ip_addr.to_string());
        node.host_name = host_name;
    }
    Ok(result)
} 
