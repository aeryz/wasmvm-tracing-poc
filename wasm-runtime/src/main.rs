use std::{fs, process};

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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FunctionCallEvent {
    pub addr: u64,
    pub data: [u8; 256],
}

fn find_perfmap_symbol(
    bin_name: &str,
    sym_suffix: &str,
) -> wasmtime::Result<Option<(u64, u64, String)>> {
    let pid = process::id();
    println!("trying to read perf map output of PID {pid}");
    let data = fs::read_to_string(format!("/tmp/perf-{pid}.map"))?;

    for line in data.lines() {
        // Example: "7f3a1c400000 00000034 world"
        let mut it = line.split_whitespace();
        let addr = it.next();
        let size = it.next();
        let name = it.next();

        if let (Some(addr), Some(size), Some(name)) = (addr, size, name) {
            println!("{} {} {}", addr, size, name);
            if name.starts_with(bin_name) && name.ends_with(sym_suffix) {
                let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16)?;
                let size = u64::from_str_radix(size, 16)?;
                return Ok(Some((addr, size, name.to_string())));
            }
        }
    }
    Ok(None)
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct Slice {
    ptr: u32,
    len: u32,
}

#[tokio::main]
async fn main() -> wasmtime::Result<()> {
    env_logger::init();
    let mut config = Config::new();
    config.profiler(ProfilingStrategy::PerfMap);
    let engine = Engine::new(&config)?;

    let module = Module::new(
        &engine,
        include_bytes!(
            "/home/aeryz/dev/ebpf/wasmvm-tracing-poc/target/wasm32-unknown-unknown/release/wasm_binary.wasm"
        ),
    )?;

    let linker = Linker::new(&engine);

    let mut store: Store<u32> = Store::new(&engine, 4);

    let instance = linker.instantiate(&mut store, &module)?;
    let memory = instance.get_memory(&mut store, "memory").unwrap();

    let alloc = instance.get_typed_func::<u32, u32>(&mut store, "alloc")?;
    // let dealloc = instance.get_typed_func::<(u32, u32), ()>(&mut store, "dealloc")?;

    let entrypoint =
        instance.get_typed_func::<(u32, u32, u32, u32, u32, u32), u32>(&mut store, "entrypoint")?;

    let x1 = write_bytes(store.as_context_mut(), &memory, &alloc, b"Hello, ")?;
    let y1 = write_bytes(store.as_context_mut(), &memory, &alloc, b"wasm!")?;

    let Some((addr, size, name)) = find_perfmap_symbol("wasm_binary", "concat_str")? else {
        panic!("oh god");
    };

    println!("world: {name} addr=0x{addr:x} size=0x{size:x}");

    let mem_base = memory.data_ptr(&store) as u64;
    tokio::task::spawn(async move {
        let mut ebpf = attach_bro(addr, mem_base).await.unwrap();
        read_events(&mut ebpf).await.unwrap();
    });

    println!("attached");

    tokio::task::spawn_blocking(|| {
        use std::io::{self, Read};
        let mut buf = [0u8; 1];
        io::stdin().read_exact(&mut buf).unwrap();
        buf[0]
    })
    .await
    .unwrap();
    println!("x1_ptr: {}", x1.ptr);
    println!("x1_len: {}", x1.len);
    println!("x1_ptr: {}", y1.ptr);
    println!("y1_len: {}", y1.len);
    println!("memory base: {:?}", memory.data_ptr(&store));
    let _ = entrypoint.call(&mut store, (x1.ptr, x1.len, y1.ptr, y1.len, 40, 2))?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn write_bytes(
    mut store: StoreContextMut<u32>,
    memory: &Memory,
    alloc: &TypedFunc<u32, u32>,
    bytes: &[u8],
) -> wasmtime::Result<Slice> {
    let ptr = alloc.call(&mut store, bytes.len() as u32)?;
    let data = memory.data_mut(&mut store);
    let start = ptr as usize;
    let end = start + bytes.len();
    if end > data.len() {
        panic!("too small")
    }
    data[start..end].copy_from_slice(bytes);
    Ok(Slice {
        ptr,
        len: bytes.len() as u32,
    })
}

async fn attach_bro(offset: u64, mem_base: u64) -> wasmtime::Result<aya::Ebpf> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::EbpfLoader::new()
        .override_global("MEM_BASE", &mem_base, true)
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/wasm-tracer-ebpf"
        )))
        .unwrap();
    let mut func_types: HashMap<_, u64, FunctionMetadata> =
        HashMap::try_from(ebpf.map_mut("FunctionTypes").expect("map exists"))?;
    func_types
        .insert(
            offset,
            &FunctionMetadata {
                param_types: [
                    ParamType::PtrSlice,
                    ParamType::PtrSlice,
                    ParamType::Unspecified,
                    ParamType::Unspecified,
                    ParamType::Unspecified,
                ],
                param_count: 2,
            },
            0,
        )
        .unwrap();
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)
                    .unwrap();
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let program: &mut PerfEvent = ebpf
        .program_mut("trace_function_call")
        .unwrap()
        .try_into()
        .unwrap();
    program.load().unwrap();
    program
        .attach(
            PerfEventConfig::Breakpoint(BreakpointConfig::Instruction { address: offset }),
            PerfEventScope::OneProcess {
                pid: std::process::id(),
                cpu: None,
            },
            SamplePolicy::Period(1),
            false,
        )
        .unwrap();

    Ok(ebpf)
}

pub async fn read_events(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let ring_buf = RingBuf::try_from(bpf.take_map("FunctionCalls").unwrap())?;
    let mut buf = tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    tokio::task::spawn(async move {
        loop {
            let mut guard = buf.readable_mut().await.unwrap();
            {
                let item = guard.get_inner_mut().next().unwrap();
                let ptr = item.as_ptr() as *const FunctionCallEvent;
                let e = unsafe { *ptr };

                let mut offset = 0;
                loop {
                    let str_len =
                        u32::from_le_bytes(e.data[offset..offset + 4].try_into().expect("works"));
                    if str_len == 0 {
                        break;
                    }
                    offset += 4;
                    let s = String::from_utf8_lossy(&e.data[offset..offset + str_len as usize]);
                    offset += str_len as usize;
                    println!("param: {s}");
                }
            }
            guard.clear_ready();
        }
    });

    println!("Waiting for Ctrl+C");
    signal::ctrl_c().await?;
    println!("Exiting..");

    Ok(())
}
