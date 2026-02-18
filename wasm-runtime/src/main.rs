use aya::{
    maps::{HashMap, RingBuf},
    programs::{
        PerfEvent,
        perf_event::{BreakpointConfig, PerfEventConfig, PerfEventScope, SamplePolicy},
    },
};
use log::{debug, warn};
use tokio::signal;
use wasm_tracer_abi::{FunctionMetadata, ParamType};
use wasmtime::{
    AsContextMut, Config, Engine, Linker, Memory, Module, ProfilingStrategy, Store,
    StoreContextMut, TypedFunc,
};

use crate::{
    ebpf_runner::EbpfRunner,
    perf_util::FunctionMapping,
    wasm_runner::{WasmRunner, WasmVM},
};

pub mod ebpf_runner;
pub mod perf_util;
pub mod wasm_runner;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FunctionCallEvent {
    pub addr: u64,
    pub data: [u8; 256],
}

struct MyWasmVM;

impl WasmVM for MyWasmVM {
    const ALLOC_FN_NAME: &str = "alloc";

    const MEMORY_NAME: &str = "memory";

    type Data = ();
}

#[tokio::main]
async fn main() -> wasmtime::Result<()> {
    env_logger::init();

    let mut wasm_runner = WasmRunner::<MyWasmVM>::load(
        "/home/aeryz/dev/ebpf/wasmvm-tracing-poc/target/wasm32-unknown-unknown/release/wasm_binary.wasm",
        (),
    )?;

    let x1 = wasm_runner.write_bytes(b"Hello, ")?;
    let y1 = wasm_runner.write_bytes(b"wasm!")?;

    let function_mapping =
        FunctionMapping::generate_from_perfmap_file_with_pid("wasm_binary", std::process::id())?;

    let mem_base = wasm_runner.get_memory_base()?;

    let mut ebpf_runner = EbpfRunner::load(
        concat!(env!("OUT_DIR"), "/wasm-tracer-ebpf"),
        mem_base,
        [
            (
                "concat_str".to_string(),
                FunctionMetadata::new_fixed([ParamType::Bytes, ParamType::Bytes]),
            ),
            (
                "add_two_numbers".to_string(),
                FunctionMetadata::new_fixed([ParamType::U32, ParamType::U32]),
            ),
            (
                "trim_ascii_whitespace".to_string(),
                FunctionMetadata::new_fixed([ParamType::Bytes]),
            ),
            (
                "collapse_ascii_spaces".to_string(),
                FunctionMetadata::new_fixed([ParamType::Bytes]),
            ),
            // (
            //     "caesar_shift_ascii".to_string(),
            //     FunctionMetadata::new_fixed([ParamType::Bytes, ParamType::I32]),
            // ),
        ]
        .into_iter()
        .collect(),
        function_mapping,
    )
    .await?;

    tokio::task::spawn(async move {
        ebpf_runner.attach_multi().unwrap();
        ebpf_runner.read_events().await.unwrap();
    });

    tokio::task::spawn_blocking(|| {
        use std::io::{self, Read};
        let mut buf = [0u8; 1];
        io::stdin().read_exact(&mut buf).unwrap();
        buf[0]
    })
    .await
    .unwrap();

    let _ = wasm_runner
        .instance
        .get_typed_func::<(u32, u32, u32, u32, u32, u32), u32>(
            &mut wasm_runner.store,
            "entrypoint",
        )?
        .call(
            &mut wasm_runner.store,
            (x1.ptr, x1.len, y1.ptr, y1.len, 40, 2),
        )?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
