use socket2::SockAddr;
use std::cmp::min;
use std::io;
use std::mem::{self, size_of, MaybeUninit};
use std::net::UdpSocket;
use std::ptr;
use std::sync::Once;
use std::time::Duration;
use winapi::ctypes::c_int;
use winapi::ctypes::c_long;
use winapi::shared::minwindef::DWORD;
use winapi::shared::mstcpip::SIO_RCVALL;
use winapi::um::winbase::INFINITE;
use winapi::um::winsock2::{self as sock, u_long, SOCKET, WSA_FLAG_NO_HANDLE_INHERIT};

pub(crate) const NO_INHERIT: c_int = 1 << ((size_of::<c_int>() * 8) - 1);
pub(crate) const MAX_BUF_LEN: usize = <c_int>::max_value() as usize;

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
    syscall!(bind(socket, addr.as_ptr(), addr.len()), PartialEq::ne, 0).map(|_| ())
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
