#![feature(str_from_raw_parts)]

use core::str;

#[inline(never)]
fn concat_str(x: &str, y: &str) -> String {
    format!("{x}{y}")
}

#[inline(never)]
fn add_two_numbers(x: u32, y: u32) -> u32 {
    x + y
}

#[repr(C)]
pub struct EntryOut {
    pub s: Slice,
    pub n: u32,
}

#[repr(C)]
pub struct Slice {
    pub ptr: *mut u8,
    pub len: usize,
}

#[inline(never)]
fn trim_ascii_whitespace(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_ascii_whitespace())
}

#[inline(never)]
fn collapse_ascii_spaces(s: &str) -> String {
    // Turns runs of ASCII whitespace into a single ' '.
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for ch in s.chars() {
        if ch.is_ascii_whitespace() {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(ch);
            in_space = false;
        }
    }
    out
}

#[inline(never)]
fn caesar_shift_ascii(s: &str, shift: u8) -> String {
    // Only shifts [a-zA-Z], leaves everything else unchanged.
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let nb = match b {
            b'a'..=b'z' => b'a' + (b - b'a' + (shift % 26)) % 26,
            b'A'..=b'Z' => b'A' + (b - b'A' + (shift % 26)) % 26,
            _ => b,
        };
        out.push(nb as char);
    }
    out
}

#[inline(never)]
fn fnv1a_32(bytes: &[u8]) -> u32 {
    // Small, deterministic, no_std-friendly hash.
    let mut h: u32 = 0x811C9DC5;
    for &b in bytes {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

#[inline(never)]
fn mix_u32(mut x: u32) -> u32 {
    // A simple avalanche-style mixer.
    x ^= x >> 16;
    x = x.wrapping_mul(0x7FEB_352D);
    x ^= x >> 15;
    x = x.wrapping_mul(0x846C_A68B);
    x ^= x >> 16;
    x
}

#[inline(never)]
fn compute_numeric(x2: u32, y2: u32, hash: u32) -> u32 {
    // Branching + loop to create more traceable function calls.
    let mut n = add_two_numbers(x2, y2);
    n ^= hash.rotate_left((hash & 31) as u32);

    // Do a few rounds so you can catch repeated call patterns.
    let rounds = 5 + ((hash >> 28) & 0x7); // 5..12
    for i in 0..rounds {
        n = mix_u32(n.wrapping_add(i));
    }

    if (hash & 1) == 0 {
        n = n.wrapping_add(0x1234_5678);
    } else {
        n = n.wrapping_sub(0x1020_3040);
    }

    n
}

#[inline(never)]
fn build_message(x1: &str, y1: &str, n: u32, hash: u32) -> String {
    // Multiple layers of string building (format + concat_str).
    let base = concat_str(x1, y1);
    let meta = format!("|n={n}|h={hash:08x}");
    concat_str(&base, &meta)
}

#[inline(never)]
fn leak_string(mut s: String) -> (u32, u32, u32) {
    // Return (ptr, len, cap) so caller can later dealloc(ptr, cap).
    let ptr = s.as_mut_ptr();
    let len = s.len();
    let cap = s.capacity();
    core::mem::forget(s);
    (ptr as u32, len as u32, cap as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

#[unsafe(no_mangle)]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    unsafe {
        drop(Vec::from_raw_parts(ptr, 0, size));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn entrypoint(
    x1_ptr: *const u8,
    x1_len: usize,
    y1_ptr: *const u8,
    y1_len: usize,
    x2: u32,
    y2: u32,
) -> *mut u8 {
    // Inputs as borrowed &str
    let x1_raw = unsafe { str::from_raw_parts(x1_ptr, x1_len) };
    let y1_raw = unsafe { str::from_raw_parts(y1_ptr, y1_len) };

    // More work + calls: trim -> collapse spaces -> caesar shift
    let x1_t = trim_ascii_whitespace(x1_raw);
    let y1_t = trim_ascii_whitespace(y1_raw);

    let x1_c = collapse_ascii_spaces(x1_t);
    let y1_c = collapse_ascii_spaces(y1_t);

    let shift = ((x2 ^ y2) & 0xFF) as u8;
    let x1_s = caesar_shift_ascii(&x1_c, shift);
    let y1_s = caesar_shift_ascii(&y1_c, shift.wrapping_add(7));

    // Hash over the transformed data
    let mut bytes = Vec::with_capacity(x1_s.len() + 1 + y1_s.len());
    bytes.extend_from_slice(x1_s.as_bytes());
    bytes.push(b'|');
    bytes.extend_from_slice(y1_s.as_bytes());
    let hash = fnv1a_32(&bytes);

    // Numeric output depends on inputs + hash
    let n = compute_numeric(x2, y2, hash);

    // Final message includes numeric + hash
    let msg = build_message(&x1_s, &y1_s, n, hash);
    let (s_ptr, s_len, _s_cap) = leak_string(msg);

    // allocate 12 bytes for EntryOut (ptr:u32, len:u32, n:u32)
    let out_ptr = alloc(12);
    unsafe {
        let p = out_ptr as *mut u8;
        *(p as *mut u32) = s_ptr;
        *(p.add(4) as *mut u32) = s_len;
        *(p.add(8) as *mut u32) = n;
    }
    out_ptr
}
