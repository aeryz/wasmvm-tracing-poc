#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::bpf_perf_event_data,
    cty::c_ulong,
    helpers::bpf_probe_read_user,
    macros::{map, perf_event},
    maps::{HashMap, RingBuf, ring_buf::RingBufBytes},
    programs::PerfEventContext,
};
use aya_log_ebpf::info;
use wasm_tracer_abi::FunctionMetadata;

pub const MAX_DATA_LEN: usize = 256;

#[map(name = "FunctionCalls")]
static FUNCTION_CALLS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map(name = "FunctionTypes")]
static FUNC_TYPES: HashMap<u64, FunctionMetadata> = HashMap::with_max_entries(1024, 0);

#[unsafe(no_mangle)]
static MEM_BASE: u64 = 0;

#[repr(C)]
pub struct FunctionCallEvent {
    pub addr: u64,
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

    let address = read_address(&ctx);

    let maybe_function_meta = unsafe { FUNC_TYPES.get(address) };
    let Some(function_meta) = maybe_function_meta else {
        return Ok(0);
    };

    let mut entry = FUNCTION_CALLS.reserve_bytes(1024, 0).ok_or(1u32)?;
    let (head, tail) = unsafe { entry.split_at_mut_unchecked(size_of::<c_ulong>()) };
    head[0..size_of::<c_ulong>()].copy_from_slice(&read_address(&ctx).to_le_bytes());

    if parse_function_params_into_buf(&ctx, mem_base, function_meta, tail).is_err() {
        return Err(discard(entry, 1));
    }

    entry.submit(0);

    Ok(0)
}

#[inline(always)]
fn parse_function_params_into_buf(
    ctx: &PerfEventContext,
    mem_base: c_ulong,
    function_meta: &FunctionMetadata,
    buf: &mut [u8],
) -> Result<u32, u32> {
    // slices consume two registers while numeric values consume only one
    let mut raw_param_offset = 0;

    let mut tail = buf;

    if function_meta.param_count > function_meta.param_types.len() {
        return Err(1);
    }
    for i in 0..function_meta.param_count {
        match function_meta.param_types[i] {
            wasm_tracer_abi::ParamType::I32 => {
                let value = read_word_at_index(ctx, raw_param_offset)?;
                let (head, new_tail) = unsafe { tail.split_at_mut_unchecked(size_of::<i32>()) };
                head.iter_mut()
                    .zip((value as i32).to_le_bytes().into_iter())
                    .for_each(|(x, y)| *x = y);

                tail = new_tail;
                raw_param_offset += 1;
            }
            wasm_tracer_abi::ParamType::I64 => {
                let value = read_word_at_index(ctx, raw_param_offset)?;
                let (head, new_tail) = unsafe { tail.split_at_mut_unchecked(size_of::<i64>()) };
                head.iter_mut()
                    .zip((value as i64).to_le_bytes().into_iter())
                    .for_each(|(x, y)| *x = y);

                tail = new_tail;
                raw_param_offset += 1;
            }
            wasm_tracer_abi::ParamType::F32 => return Err(0),
            wasm_tracer_abi::ParamType::F64 => return Err(0),
            wasm_tracer_abi::ParamType::PtrSlice => {
                let pointer = read_word_at_index(ctx, raw_param_offset)?;
                let len = read_word_at_index(ctx, raw_param_offset + 1)?;

                // TODO(aeryz): this check is wrong
                if len > 20 as u64 {
                    return Err(1);
                }

                let (head, new_tail) = unsafe { tail.split_at_mut_unchecked(4) };
                head.iter_mut()
                    .zip((len as u32).to_le_bytes().into_iter())
                    .for_each(|(x, y)| *x = y);
                tail = new_tail;

                let (head, new_tail) = unsafe { tail.split_at_mut_unchecked(len as usize) };
                head.iter_mut().enumerate().try_for_each(|(i, x)| {
                    unsafe {
                        *x = bpf_probe_read_user((mem_base + pointer + i as u64) as *const u8)
                            .map_err(|x| x as u32)?;
                    }

                    Result::<(), u32>::Ok(())
                })?;

                tail = new_tail;
                raw_param_offset += 2;
            }
            _ => return Err(0),
        }
    }
    Ok(0)
}

#[inline(always)]
/// Reads a single word at an `index` based on the [System V calling convention](https://wiki.osdev.org/System_V_ABI)
fn read_word_at_index(ctx: &PerfEventContext, index: usize) -> Result<c_ulong, u32> {
    let val = match index {
        0 => read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.rcx) }),
        1 => read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.r8) }),
        2 => read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.r9) }),
        n => {
            let stack_ptr = read_register(&ctx, |p| unsafe { core::ptr::addr_of!((*p).regs.rsp) });
            // `n - 2` since n starts from 3
            let stack_offset = (size_of::<c_ulong>() * (n - 2)) as c_ulong;
            unsafe {
                bpf_probe_read_user((stack_ptr + stack_offset) as *const c_ulong)
                    .map_err(|e| e as u32)?
            }
        }
    };

    Ok(val)
}

#[inline(always)]
fn read_register(
    ctx: &PerfEventContext,
    addr_of_reg: fn(*const bpf_perf_event_data) -> *const u64,
) -> c_ulong {
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
