use socket2::SockAddr;
use std::cmp::min;
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::UdpSocket;
use std::ptr;
use std::sync::Once;
use std::time::Duration;

#[allow(non_camel_case_types)]
type c_int = i32;

#[allow(non_camel_case_types)]
type c_long = i32;

type DWORD = u32;
use windows_sys::Win32::Networking::WinSock::SIO_RCVALL;
use windows_sys::Win32::System::Threading::INFINITE;

#[allow(non_camel_case_types)]
type u_long = u32;

use windows_sys::Win32::Networking::WinSock::{self as sock, SOCKET, WSA_FLAG_NO_HANDLE_INHERIT};

pub(crate) const NO_INHERIT: c_int = 1 << (c_int::BITS - 1);
pub(crate) const MAX_BUF_LEN: usize = <c_int>::max_value() as usize;

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ), $err_test: path, $err_value: expr) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { windows_sys::Win32::Networking::WinSock::$fn($($arg, )*) };
        if $err_test(&res, &$err_value) {
            Err(io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

pub(crate) fn init_socket() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = UdpSocket::bind("127.0.0.1:34254");
    });
}

pub(crate) fn ioctlsocket(socket: SOCKET, cmd: c_long, payload: &mut u_long) -> io::Result<()> {
    syscall!(
        ioctlsocket(socket, cmd, payload),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

pub(crate) fn create_socket(family: c_int, mut ty: c_int, protocol: c_int) -> io::Result<SOCKET> {
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

pub(crate) fn bind(socket: SOCKET, addr: &SockAddr) -> io::Result<()> {
    // Convert the SockAddr reference to a raw pointer, which is required by the Windows API,
    // and pass it to the `bind` function to associate the socket with the provided address.
    // This is necessary for compatibility with the `windows-sys` crate.
    let sockaddr = addr.as_ptr() as *const _;
    syscall!(bind(socket, sockaddr, addr.len()), PartialEq::ne, 0).map(|_| ())
}

#[allow(dead_code)]
pub(crate) fn set_nonblocking(socket: SOCKET, nonblocking: bool) -> io::Result<()> {
    let mut nonblocking = nonblocking as u_long;
    ioctlsocket(socket, sock::FIONBIO, &mut nonblocking)
}

pub(crate) fn set_promiscuous(socket: SOCKET, promiscuous: bool) -> io::Result<()> {
    let mut promiscuous = promiscuous as u_long;
    ioctlsocket(socket, SIO_RCVALL as i32, &mut promiscuous)
}

pub(crate) unsafe fn setsockopt<T>(
    socket: SOCKET,
    level: c_int,
    optname: i32,
    optval: T,
) -> io::Result<()> {
    syscall!(
        setsockopt(
            socket,
            level as i32,
            optname,
            (&optval as *const T).cast(),
            mem::size_of::<T>() as c_int,
        ),
        PartialEq::eq,
        sock::SOCKET_ERROR
    )
    .map(|_| ())
}

pub(crate) fn into_ms(duration: Option<Duration>) -> DWORD {
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

pub(crate) fn recv_from(
    socket: SOCKET,
    buf: &mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, SockAddr)> {
    unsafe {
        SockAddr::try_init(|storage, addrlen| {
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
