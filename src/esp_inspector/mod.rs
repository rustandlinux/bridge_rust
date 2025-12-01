use byteorder::{BigEndian, ByteOrder};

// --- ANSI Colors ---
const COLOR_RESET: &str = "\x1b[0m";
const COLOR_GREY: &str = "\x1b[90m";
const COLOR_RED: &str = "\x1b[91m";
const COLOR_GREEN: &str = "\x1b[92m";
const COLOR_YELLOW: &str = "\x1b[93m";
const COLOR_BLUE: &str = "\x1b[94m";
const COLOR_MAGENTA: &str = "\x1b[95m";
const COLOR_CYAN: &str = "\x1b[96m";

fn print_hex(data: &[u8], regions: &[(usize, usize, &'static str)]) {
    let mut color_map = vec![COLOR_RESET; data.len()];
    for &(s, e, c) in regions {
        let end = e.min(data.len());
        for i in s..end {
            color_map[i] = c;
        }
    }

    let mut offset = 0usize;
    while offset < data.len() {
        print!("{}{:04x}  {}", COLOR_GREY, offset, COLOR_RESET);

        for j in 0..16 {
            if offset + j < data.len() {
                let c = color_map[offset + j];
                print!("{}{:02x}{} ", c, data[offset + j], COLOR_RESET);
            } else {
                print!("   ");
            }
            if j == 7 {
                print!(" ");
            }
        }

        print!(" ");
        for j in 0..16 {
            if offset + j < data.len() {
                let c = color_map[offset + j];
                let char = data[offset + j] as char;
                if char.is_ascii_graphic() {
                    print!("{}{}{}", c, char, COLOR_RESET);
                } else {
                    print!(".");
                }
            }
        }
        println!();
        offset += 16;
    }
}

/// 检查并打印 ESP 报文 (现在包含 IV)
pub fn inspect_esp_packet(buf: &[u8], direction: &str, icv_len: usize) {
    if buf.len() < 14 + 20 {
        return;
    }
    if BigEndian::read_u16(&buf[12..14]) != 0x0800 {
        return;
    }

    let ip = &buf[14..];
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ip.len() < ihl {
        return;
    }
    if ip[9] != 50 {
        return;
    }

    let esp_hdr_len = 8;
    let iv_len = 16; // SM4-CBC IV length
    let esp_start = 14 + ihl;
    if buf.len() < esp_start + esp_hdr_len + iv_len + icv_len {
        return;
    }

    let esp = &ip[ihl..];
    let spi = BigEndian::read_u32(&esp[0..4]);
    let seq = BigEndian::read_u32(&esp[4..8]);

    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);

    println!(
        "\n[ESP] {} | {} -> {} | SPI=0x{:x}, Seq={}",
        direction, src, dst, spi, seq
    );

    let eth_len = 14;
    let ip_len = ihl;

    let enc_data_len = buf.len() - eth_len - ip_len - esp_hdr_len - iv_len - icv_len;

    let eth_region = (0, eth_len, COLOR_BLUE);
    let ip_region = (eth_len, eth_len + ip_len, COLOR_GREEN);
    let esp_hdr_region = (ip_region.1, ip_region.1 + esp_hdr_len, COLOR_YELLOW);
    let iv_region = (esp_hdr_region.1, esp_hdr_region.1 + iv_len, COLOR_CYAN);
    let enc_region = (iv_region.1, iv_region.1 + enc_data_len, COLOR_RED);
    let icv_region = (enc_region.1, enc_region.1 + icv_len, COLOR_MAGENTA);

    let regions = vec![
        eth_region,
        ip_region,
        esp_hdr_region,
        iv_region,
        enc_region,
        icv_region,
    ];

    println!(
        "    Legend: {}[Eth]{} {}[IP]{} {}[ESP]{} {}[IV]{} {}[Encrypted]{} {}[ICV]{}",
        COLOR_BLUE,
        COLOR_RESET,
        COLOR_GREEN,
        COLOR_RESET,
        COLOR_YELLOW,
        COLOR_RESET,
        COLOR_CYAN,
        COLOR_RESET,
        COLOR_RED,
        COLOR_RESET,
        COLOR_MAGENTA,
        COLOR_RESET
    );
    println!(
        "    Lengths: Total={} | Eth={} | IP={} | ESP={} | IV={} | Encrypted={} | ICV={}",
        buf.len(),
        eth_len,
        ip_len,
        esp_hdr_len,
        iv_len,
        enc_data_len,
        icv_len
    );

    let dump_end = std::cmp::min(icv_region.1, buf.len());
    print_hex(&buf[..dump_end], &regions);
}
