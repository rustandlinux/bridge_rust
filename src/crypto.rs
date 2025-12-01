use byteorder::{BigEndian, ByteOrder};
use hmac::{Hmac, Mac};
use openssl::symm::{Cipher, Crypter, Mode};
use sm3::Sm3;

// --- 密钥和 SPI 常量 ---
const SPI_S1_D2: u32 = 0x00000301;
const SPI_S2_D1: u32 = 0x00000302;
const AUTH_KEY_S1_D2: [u8; 32] = [
    0x96, 0x35, 0x8c, 0x90, 0x78, 0x3b, 0xbf, 0xa3, 0xd7, 0xb1, 0x96, 0xce, 0xab, 0xe0, 0x53, 0x6b,
    0x96, 0x35, 0x8c, 0x90, 0x78, 0x3b, 0xbf, 0xa3, 0xd7, 0xb1, 0x96, 0xce, 0xab, 0xe0, 0x53, 0x6b,
];
const AUTH_KEY_S2_D1: [u8; 32] = [
    0x99, 0x35, 0x8c, 0x90, 0x78, 0x3b, 0xbf, 0xa3, 0xd7, 0xb1, 0x96, 0xce, 0xab, 0xe0, 0x53, 0x6b,
    0x99, 0x35, 0x8c, 0x90, 0x78, 0x3b, 0xbf, 0xa3, 0xd7, 0xb1, 0x96, 0xce, 0xab, 0xe0, 0x53, 0x6b,
];
const ENC_KEY_S1_D2: [u8; 16] = [
    0xf6, 0xdd, 0xb5, 0x55, 0xac, 0xfd, 0x9d, 0x77, 0xb0, 0x3e, 0xa3, 0x84, 0x3f, 0x26, 0x53, 0x25,
];
const ENC_KEY_S2_D1: [u8; 16] = [
    0xff, 0xdd, 0xb5, 0x55, 0xac, 0xfd, 0x9d, 0x77, 0xb0, 0x3e, 0xa3, 0x84, 0x3f, 0x26, 0x53, 0x25,
];

const SM4_IV_LEN: usize = 16;
const TEMP_BUF_SIZE: usize = 2048; // Must be larger than typical MTU

/// 就地加密 ESP 报文的明文负载
pub fn encrypt_in_place(
    packet: &mut [u8],
    original_len: usize,
    icv_len: usize,
) -> Result<usize, &'static str> {
    // 1. 解析 IP 和 ESP 头部
    let ip_hdr_start = 14;
    if original_len < ip_hdr_start + 20 {
        return Err("Packet too short for IP header");
    }
    let ihl = (packet[ip_hdr_start] & 0x0f) as usize * 4;
    if original_len < ip_hdr_start + ihl {
        return Err("Packet too short for full IP header");
    }

    let esp_hdr_start = ip_hdr_start + ihl;
    let esp_hdr_len = 8;
    let iv_len = SM4_IV_LEN;
    if original_len < esp_hdr_start + esp_hdr_len + iv_len + icv_len {
        return Err("Packet too short for ESP structure");
    }

    let spi = BigEndian::read_u32(&packet[esp_hdr_start..]);
    let (enc_key, auth_key) = match spi {
        SPI_S1_D2 => (&ENC_KEY_S1_D2, &AUTH_KEY_S1_D2),
        SPI_S2_D1 => (&ENC_KEY_S2_D1, &AUTH_KEY_S2_D1),
        _ => return Err("Unknown SPI for encryption"),
    };

    // 2. 提取明文负载
    let plaintext_start = esp_hdr_start + esp_hdr_len + iv_len;
    let plaintext_len = original_len - plaintext_start - icv_len;

    if plaintext_len + 16 > TEMP_BUF_SIZE {
        // 确保临时缓冲区足够大
        return Err("Packet payload too large for optimization buffer");
    }

    // 3. 使用栈上临时缓冲区作为输出来执行加密
    let mut temp_ciphertext = [0u8; TEMP_BUF_SIZE];

    let plaintext_slice = &packet[plaintext_start..plaintext_start + plaintext_len];
    let iv = &packet[esp_hdr_start + esp_hdr_len..plaintext_start];

    let mut crypter = Crypter::new(Cipher::sm4_cbc(), Mode::Encrypt, enc_key, Some(iv))
        .map_err(|_| "Failed to create crypter")?;
    crypter.pad(false);

    let mut count = crypter
        .update(plaintext_slice, &mut temp_ciphertext)
        .map_err(|_| "Encryption update failed")?;
    count += crypter
        .finalize(&mut temp_ciphertext[count..])
        .map_err(|_| "Encryption finalize failed")?;

    if count != plaintext_len {
        return Err("Ciphertext length mismatch after encryption");
    }

    // 4. 将加密结果从临时缓冲区拷贝回原报文
    packet[plaintext_start..plaintext_start + count].copy_from_slice(&temp_ciphertext[..count]);

    // 5. 计算并更新 ICV
    let data_to_auth_end = plaintext_start + count;
    let data_to_auth = &packet[esp_hdr_start..data_to_auth_end];
    let mut hmac_sm3 = <Hmac<Sm3> as Mac>::new_from_slice(auth_key).unwrap();
    hmac_sm3.update(data_to_auth);
    let icv_bytes = hmac_sm3.finalize().into_bytes();
    let icv_start = data_to_auth_end;
    packet[icv_start..icv_start + icv_len].copy_from_slice(&icv_bytes[..icv_len]);

    Ok(original_len)
}

/// 就地解密 ESP 报文的负载 (保持ESP结构)
pub fn decrypt_in_place(
    packet: &mut [u8],
    len: usize,
    icv_len: usize,
) -> Result<usize, &'static str> {
    // 1. 解析 IP 和 ESP 头部
    let ip_hdr_start = 14;
    if len < ip_hdr_start + 20 {
        return Err("Packet too short for IP header");
    }
    let ihl = (packet[ip_hdr_start] & 0x0f) as usize * 4;
    if len < ip_hdr_start + ihl {
        return Err("Packet too short for full IP header");
    }

    let esp_hdr_start = ip_hdr_start + ihl;
    let esp_hdr_len = 8;
    let iv_len = SM4_IV_LEN;
    if len < esp_hdr_start + esp_hdr_len + iv_len + icv_len {
        return Err("Packet too short for ESP structure");
    }

    let spi = BigEndian::read_u32(&packet[esp_hdr_start..]);
    let (enc_key, auth_key) = match spi {
        SPI_S1_D2 => (&ENC_KEY_S1_D2, &AUTH_KEY_S1_D2),
        SPI_S2_D1 => (&ENC_KEY_S2_D1, &AUTH_KEY_S2_D1),
        _ => return Err("Unknown SPI for decryption"),
    };

    // 2. 验证 ICV
    /*
    let data_to_auth = &packet[esp_hdr_start .. len - icv_len];
    let received_icv = &packet[len - icv_len .. len];
    let mut hmac_sm3 = <Hmac<Sm3> as Mac>::new_from_slice(auth_key).unwrap();
    hmac_sm3.update(data_to_auth);
    hmac_sm3.verify_slice(&received_icv[..icv_len]).map_err(|_| "ICV verification failed!")?;
    */
    // 3. 提取密文并使用栈上临时缓冲区执行解密
    let ciphertext_start = esp_hdr_start + esp_hdr_len + iv_len;
    let ciphertext_len = len - ciphertext_start - icv_len;

    if ciphertext_len + 16 > TEMP_BUF_SIZE {
        return Err("Packet payload too large for optimization buffer");
    }

    let mut temp_plaintext = [0u8; TEMP_BUF_SIZE];

    let ciphertext_slice = &packet[ciphertext_start..ciphertext_start + ciphertext_len];
    let iv = &packet[esp_hdr_start + esp_hdr_len..ciphertext_start];

    let mut crypter = Crypter::new(Cipher::sm4_cbc(), Mode::Decrypt, enc_key, Some(iv))
        .map_err(|_| "Failed to create crypter")?;
    crypter.pad(false);

    let mut count = crypter
        .update(ciphertext_slice, &mut temp_plaintext)
        .map_err(|_| "Decryption update failed")?;
    count += crypter
        .finalize(&mut temp_plaintext[count..])
        .map_err(|_| "Decryption finalize failed")?;

    if count != ciphertext_len {
        return Err("Plaintext length mismatch after decryption");
    }

    // 4. 将解密结果从临时缓冲区拷贝回原报文
    packet[ciphertext_start..ciphertext_start + count].copy_from_slice(&temp_plaintext[..count]);

    // 5. 为解密后的报文重新计算并更新 ICV
    let data_to_auth_end = ciphertext_start + count;
    let new_data_to_auth = &packet[esp_hdr_start..data_to_auth_end];
    let mut new_hmac_sm3 = <Hmac<Sm3> as Mac>::new_from_slice(auth_key).unwrap();
    new_hmac_sm3.update(new_data_to_auth);
    let new_icv_bytes = new_hmac_sm3.finalize().into_bytes();
    let icv_start = data_to_auth_end;
    packet[icv_start..icv_start + icv_len].copy_from_slice(&new_icv_bytes[..icv_len]);

    Ok(len)
}
