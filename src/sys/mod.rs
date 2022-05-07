#[cfg(target_os="windows")]
pub(crate) mod windows;
#[cfg(target_os="windows")]
pub(crate) use self::windows::*;

pub(crate) fn guess_initial_ttl(ttl: u8) -> u8 {
    if ttl <= 64 {
        64
    }else if 64 < ttl && ttl <= 128 {
        128
    }else {
        255
    }
}
