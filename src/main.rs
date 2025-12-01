use byteorder::{BigEndian, ByteOrder};
use clap::Parser;

use nix::poll::{poll, PollFd, PollFlags};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod crypto;
mod esp_inspector;
mod raw_socket;

#[derive(Parser, Debug)]
#[command(author, version, about = "L2 bridge with ESP crypto gateway (Rust)")]
struct Args {
    iface1: String,
    iface2: String,
    #[arg(long = "icv-len", default_value_t = 32)]
    icv_len: usize,
    /// Enable debug packet printing
    #[arg(long)]
    debug: bool,
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    if unsafe { libc::geteuid() } != 0 {
        eprintln!("This program requires root privileges. Run with sudo.");
        std::process::exit(1);
    }

    let fd1 = raw_socket::open_raw_socket(&args.iface1)?;
    let fd2 = raw_socket::open_raw_socket(&args.iface2)?;

    println!(
        "Crypto Gateway running: {} (plain) <--> {} (crypto) (ICV={} bytes)",
        args.iface1, args.iface2, args.icv_len
    );

    let running = Arc::new(AtomicBool::new(true));
    ctrlc::set_handler({
        let r = running.clone();
        move || r.store(false, Ordering::SeqCst)
    })
    .expect("failed to set Ctrl-C handler");

    let mut pfd = [
        PollFd::new(fd1, PollFlags::POLLIN),
        PollFd::new(fd2, PollFlags::POLLIN),
    ];

    let mut buf = vec![0u8; 65536];
    let mut pkt_count1_to_2: u64 = 0;
    let mut pkt_count2_to_1: u64 = 0;
    let mut bytes_count1_to_2: u64 = 0;
    let mut bytes_count2_to_1: u64 = 0;
    let mut last_stats = Instant::now();

    while running.load(Ordering::SeqCst) {
        if poll(&mut pfd, 200).is_err() && nix::errno::errno() != libc::EINTR {
            return Err(io::Error::last_os_error());
        }

        // --- 从 iface1 (src) 接收，加密后发往 iface2 (dst) ---
        if pfd[0]
            .revents()
            .unwrap_or(PollFlags::empty())
            .contains(PollFlags::POLLIN)
        {
            if let Ok(n) =
                unsafe { libc::recv(fd1, buf.as_mut_ptr() as *mut _, buf.len(), 0).try_into() }
            {
                if n > 0 {
                    let is_esp_packet = n >= 14 + 20 && // Min Eth + IP len
                                        BigEndian::read_u16(&buf[12..14]) == 0x0800 && // IPv4
                                        buf[14 + 9] == 50; // Protocol == ESP

                    if is_esp_packet {
                        if args.debug {
                            esp_inspector::inspect_esp_packet(
                                &buf[..n],
                                "<-- PLAINTEXT ESP",
                                args.icv_len,
                            );
                        }
                        match crypto::encrypt_in_place(&mut buf, n, args.icv_len) {
                            Ok(final_len) => {
                                if args.debug {
                                    esp_inspector::inspect_esp_packet(
                                        &buf[..final_len],
                                        "--> ENCRYPTED",
                                        args.icv_len,
                                    );
                                }
                                unsafe { libc::send(fd2, buf.as_ptr() as *const _, final_len, 0) };
                                pkt_count1_to_2 += 1;
                                bytes_count1_to_2 += final_len as u64;
                            }
                            Err(e) => eprintln!("[{}] Encrypt failed: {}", args.iface1, e),
                        }
                    } else {
                        // 非 ESP 报文 (如 ARP), 直接转发
                        unsafe { libc::send(fd2, buf.as_ptr() as *const _, n, 0) };
                    }
                }
            }
        }

        // --- 从 iface2 (dst) 接收，解密后发往 iface1 (src) ---
        if pfd[1]
            .revents()
            .unwrap_or(PollFlags::empty())
            .contains(PollFlags::POLLIN)
        {
            if let Ok(n) =
                unsafe { libc::recv(fd2, buf.as_mut_ptr() as *mut _, buf.len(), 0).try_into() }
            {
                if n > 0 {
                    let is_esp_packet = n >= 14 + 20 && // Min Eth + IP len
                                        BigEndian::read_u16(&buf[12..14]) == 0x0800 && // IPv4
                                        buf[14 + 9] == 50; // Protocol == ESP

                    if is_esp_packet {
                        if args.debug {
                            esp_inspector::inspect_esp_packet(
                                &buf[..n],
                                "<-- ENCRYPTED",
                                args.icv_len,
                            );
                        }
                        match crypto::decrypt_in_place(&mut buf, n, args.icv_len) {
                            Ok(final_len) => {
                                if args.debug {
                                    esp_inspector::inspect_esp_packet(
                                        &buf[..final_len],
                                        "--> DECRYPTED (in ESP)",
                                        args.icv_len,
                                    );
                                }
                                unsafe { libc::send(fd1, buf.as_ptr() as *const _, final_len, 0) };
                                pkt_count2_to_1 += 1;
                                bytes_count2_to_1 += final_len as u64;
                            }
                            Err(e) => eprintln!("[{}] Decrypt failed: {}", args.iface2, e),
                        }
                    } else {
                        // 非 ESP 报文 (如 ARP), 直接转发
                        unsafe { libc::send(fd1, buf.as_ptr() as *const _, n, 0) };
                    }
                }
            }
        }

        let now = Instant::now();
        let elapsed = now.duration_since(last_stats);
        if elapsed >= Duration::from_secs(1) {
            let elapsed_secs = elapsed.as_secs_f64();

            let gbps1_to_2 = (bytes_count1_to_2 as f64 * 8.0) / (elapsed_secs * 1_000_000_000.0);
            let gbps2_to_1 = (bytes_count2_to_1 as f64 * 8.0) / (elapsed_secs * 1_000_000_000.0);

            println!(
                "Stats: {:.3} Gbps, {} pps ({} -> {}) | {:.3} Gbps, {} pps ({} <- {})",
                gbps1_to_2,
                pkt_count1_to_2,
                args.iface1,
                args.iface2,
                gbps2_to_1,
                pkt_count2_to_1,
                args.iface1,
                args.iface2
            );

            // Reset counters for the next interval
            pkt_count1_to_2 = 0;
            pkt_count2_to_1 = 0;
            bytes_count1_to_2 = 0;
            bytes_count2_to_1 = 0;
            last_stats = now;
        }
    }

    println!("\nClosing sockets.");
    unsafe {
        libc::close(fd1);
        libc::close(fd2);
    }

    Ok(())
}
