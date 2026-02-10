#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::bpf_perf_event_data,
    cty::c_long,
    helpers::{bpf_probe_read, bpf_probe_read_user_str_bytes},
    macros::{perf_event, uprobe},
    programs::{PerfEventContext, ProbeContext, RetProbeContext},
};
use aya_log_ebpf::info;

#[perf_event]
pub fn trace_function_call(ctx: PerfEventContext) -> u32 {
    match try_trace_function_call(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_trace_function_call(ctx: PerfEventContext) -> Result<u32, u32> {
    info!(&ctx, "entered bro omg");

    let inner = unsafe { *ctx.ctx };

    info!(&ctx, "regs: {}", inner.regs.rdx);

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
