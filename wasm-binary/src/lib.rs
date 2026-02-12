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

#[unsafe(no_mangle)]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
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
    let x1 = unsafe { str::from_raw_parts(x1_ptr, x1_len) };
    let y1 = unsafe { str::from_raw_parts(y1_ptr, y1_len) };
    let (s, s_len, _) = concat_str(&x1, &y1).into_raw_parts();
    let n = add_two_numbers(x2, y2);

    // allocate 12 bytes for EntryOut
    let out_ptr = alloc(12);
    unsafe {
        let p = out_ptr as *mut u8;
        *(p as *mut u32) = s as u32;
        *(p.add(4) as *mut u32) = s_len as u32;
        *(p.add(8) as *mut u32) = n;
    }
    out_ptr
}
