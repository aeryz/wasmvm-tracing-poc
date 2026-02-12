#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_perf_event_data,
    cty::c_void,
    helpers::{bpf_probe_read_user, generated},
    macros::{map, perf_event},
    maps::{
        RingBuf,
        ring_buf::{RingBufBytes, RingBufEntry},
    },
    programs::PerfEventContext,
};
use aya_log_ebpf::info;

pub const MAX_DATA_LEN: usize = 256;

#[map(name = "FunctionCalls")]
static FUNCTION_CALLS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[unsafe(no_mangle)]
static MEM_BASE: u64 = 0;

#[repr(C)]
pub struct FunctionCallEvent {
    pub addr: u64,
    pub len: u32,
    pub data: [u8; MAX_DATA_LEN],
}

#[perf_event]
pub fn trace_function_call(ctx: PerfEventContext) -> u32 {
    match try_trace_function_call(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn discard(entry: RingBufBytes<'_>, e: u32) -> u32 {
    entry.discard(0);
    e
}

fn try_trace_function_call(ctx: PerfEventContext) -> Result<u32, u32> {
    info!(&ctx, "within the probe");

    let mem_base = unsafe { core::ptr::read_volatile(&MEM_BASE) };

    let first_str_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.rcx) });
    let first_str_len = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.r8) });
    let second_str_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.r9) });
    let stack_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.rsp) });
    let second_str_len =
        unsafe { bpf_probe_read_user((stack_ptr + 8) as *const usize).map_err(|e| e as u32)? };

    let mut entry = FUNCTION_CALLS.reserve_bytes(1024, 0).ok_or(1u32)?;

    let (head, tail) = unsafe { entry.split_at_mut_unchecked(12) };
    head[0..8].copy_from_slice(&read_address(&ctx).to_le_bytes());
    head[8..12]
        .copy_from_slice(&(4 * 2 + first_str_len as u32 + second_str_len as u32).to_le_bytes());

    let (head, tail) = unsafe { tail.split_at_mut_unchecked(4) };
    head.iter_mut()
        .zip((first_str_len as u32).to_le_bytes().into_iter())
        .for_each(|(x, y)| {
            *x = y;
        });

    if first_str_len > MAX_DATA_LEN as u64 {
        return Err(discard(entry, 1));
    }

    let (head, tail) = unsafe { tail.split_at_mut_unchecked(first_str_len as usize) };
    if head
        .iter_mut()
        .enumerate()
        .try_for_each(|(i, x)| {
            unsafe {
                *x = bpf_probe_read_user((mem_base + first_str_ptr + i as u64) as *const u8)
                    .map_err(|x| x as u32)?;
            }

            Result::<(), u32>::Ok(())
        })
        .is_err()
    {
        return Err(discard(entry, 1));
    }

    let (head, tail) = unsafe { tail.split_at_mut_unchecked(4) };
    head.iter_mut()
        .zip((second_str_len as u32).to_le_bytes().into_iter())
        .for_each(|(x, y)| {
            *x = y;
        });

    if second_str_len > MAX_DATA_LEN {
        return Err(discard(entry, 1));
    }

    let (head, _) = unsafe { tail.split_at_mut_unchecked(second_str_len as usize) };
    if head
        .iter_mut()
        .enumerate()
        .try_for_each(|(i, x)| {
            unsafe {
                *x = bpf_probe_read_user((mem_base + second_str_ptr + i as u64) as *const u8)
                    .map_err(|x| x as u32)?;
            }

            Result::<(), u32>::Ok(())
        })
        .is_err()
    {
        return Err(discard(entry, 1));
    }

    entry.submit(0);

    Ok(0)
}

#[inline(always)]
fn read_user_str_into_buf(
    entry: &mut RingBufEntry<FunctionCallEvent>,
    offset: u32,
    ptr: u64,
    len: usize,
) -> Result<(), ()> {
    let e = unsafe { entry.assume_init_mut() };
    if len > 32 {
        unsafe {
            if offset as usize > 256 {
                return Err(());
            }
            if generated::bpf_probe_read_user(
                e.data.as_mut_ptr().add(offset as usize) as *mut c_void,
                32,
                ptr as *const c_void,
            ) != 0
            {
                return Err(());
            }
        }
    }

    Ok(())
}

#[inline(always)]
fn read_register(
    ctx: &PerfEventContext,
    addr_of_reg: fn(*const bpf_perf_event_data) -> *const u64,
) -> u64 {
    let p = ctx.ctx as *const bpf_perf_event_data;

    unsafe { core::ptr::read_volatile(addr_of_reg(p)) }
}

#[inline(always)]
fn read_address(ctx: &PerfEventContext) -> u64 {
    let p = ctx.ctx as *const bpf_perf_event_data;

    unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*p).addr)) as u64 }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
