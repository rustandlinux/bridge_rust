use libc;
use std::io;
use std::mem;
use std::os::unix::io::RawFd;

const ETH_P_ALL: u16 = 0x0003; // host order; htons when used

#[repr(C)]
struct PacketMreq {
    mr_ifindex: libc::c_int,
    mr_type: libc::c_ushort,
    mr_alen: libc::c_ushort,
    mr_address: [u8; 8],
}

fn if_index(ifname: &str) -> io::Result<u32> {
    let cstr = std::ffi::CString::new(ifname)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if idx == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

pub fn open_raw_socket(ifname: &str) -> io::Result<RawFd> {
    // socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            libc::htons(ETH_P_ALL) as libc::c_int,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // bind to interface
    let ifidx = if_index(ifname)? as i32;
    let sll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: libc::htons(ETH_P_ALL),
        sll_ifindex: ifidx,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };

    let bind_ret = unsafe {
        libc::bind(
            fd,
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if bind_ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    // enter promiscuous
    let mreq = PacketMreq {
        mr_ifindex: ifidx,
        mr_type: libc::PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0u8; 8],
    };

    let setsock_ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            mem::size_of::<PacketMreq>() as libc::socklen_t,
        )
    };
    if setsock_ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    // non-blocking
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }

    Ok(fd)
}
