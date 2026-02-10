use std::{fs, process};

use aya::programs::{
    PerfEvent,
    perf_event::{BreakpointConfig, PerfEventConfig, PerfEventScope, SamplePolicy},
};
use log::{debug, warn};
use tokio::signal;
use wasmtime::{Config, Engine, Linker, Module, ProfilingStrategy, Store};

fn find_perfmap_symbol(sym_suffix: &str) -> wasmtime::Result<Option<(u64, u64, String)>> {
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
            if name.ends_with(sym_suffix) {
                let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16)?;
                let size = u64::from_str_radix(size, 16)?;
                return Ok(Some((addr, size, name.to_string())));
            }
        }
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> wasmtime::Result<()> {
    env_logger::init();
    let mut config = Config::new();
    config.profiler(ProfilingStrategy::PerfMap);
    let engine = Engine::new(&config)?;

    // Modules can be compiled through either the text or binary format
    let wat = r#"
    (module
        (func $one_param (export "one_param") (param i32)
            local.get 0
            drop)
        (func $two_params (export "two_params") (param i32 i64)
            local.get 0
            drop
            local.get 1
            drop)
        (func $three_params (export "three_params") (param i64 i64 i64)
            local.get 0
            drop
            local.get 1
            drop
            local.get 2
            drop)
        (func (export "hello")
            i32.const 10
            call $one_param
            i32.const 100
            i64.const 1000
            call $two_params
            i64.const 10000
            i64.const 100000
            i64.const 1000000
            call $three_params
            )
        )
    "#;
    let module = Module::new(&engine, wat)?;
    let wasm_bin = wat::parse_str(wat)?;

    fs::write("./out.wasm", wasm_bin)?;

    // // Host functionality can be arbitrary Rust functions and is provided
    // // to guests through a `Linker`.
    let linker = Linker::new(&engine);

    // linker.func_wrap(
    //     "host",
    //     "host_func",
    //     |caller: Caller<'_, u32>, param: i32| {
    //         println!("Got {} from WebAssembly", param);
    //         println!("my host state is: {}", caller.data());
    //     },
    // )?;

    // All wasm objects operate within the context of a "store". Each
    // `Store` has a type parameter to store host-specific data, which in
    // this case we're using `4` for.
    let mut store: Store<u32> = Store::new(&engine, 4);

    // Instantiation of a module requires specifying its imports and then
    // afterwards we can fetch exports by name, as well as asserting the
    // type signature of the function with `get_typed_func`.
    let instance = linker.instantiate(&mut store, &module)?;
    let hello = instance.get_typed_func::<(), ()>(&mut store, "hello")?;

    // And finally we can call the wasm!
    // hello.call(&mut store, ())?;

    let Some((addr, size, name)) = find_perfmap_symbol("two_params")? else {
        panic!("oh god");
    };

    println!("world: {name} addr=0x{addr:x} size=0x{size:x}");

    let ebpf = attach_bro(addr).await.unwrap();

    println!("attached");

    tokio::task::spawn_blocking(|| {
        use std::io::{self, Read};
        let mut buf = [0u8; 1];
        io::stdin().read_exact(&mut buf).unwrap();
        buf[0]
    })
    .await
    .unwrap();
    hello.call(&mut store, ())?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

async fn attach_bro(offset: u64) -> wasmtime::Result<aya::Ebpf> {
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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(
        "/home/aeryz/dev/ebpf/wasmvm-tracing-poc/out.bpf.o"
    ))
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
        .program_mut("uprobe_bashreadline")
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
