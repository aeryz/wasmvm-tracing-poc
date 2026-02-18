use std::{collections::HashMap, fs, path::Path};

use aya::{
    Ebpf,
    maps::{HashMap as EbpfHashMap, RingBuf},
    programs::{
        PerfEvent,
        perf_event::{BreakpointConfig, PerfEventConfig, PerfEventScope, SamplePolicy},
    },
};
use log::warn;

use crate::{FunctionCallEvent, perf_util::FunctionMapping};

pub struct EbpfRunner {
    ebpf: Ebpf,
    traced_addresses: Vec<u64>,
}

impl EbpfRunner {
    pub async fn load<P: AsRef<Path>>(
        path: P,
        mem_base: u64,
        function_abi: HashMap<String, wasm_tracer_abi::FunctionMetadata>,
        mapping: FunctionMapping,
    ) -> anyhow::Result<Self> {
        let mut ebpf = aya::EbpfLoader::new()
            .override_global("MEM_BASE", &mem_base, true)
            .load(&fs::read(path)?)
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

        let mut func_types: EbpfHashMap<_, u64, wasm_tracer_abi::FunctionMetadata> =
            EbpfHashMap::try_from(ebpf.map_mut("FunctionTypes").expect("map exists"))?;

        let mut traced_addresses = Vec::new();

        mapping.into_iter().for_each(|(addr, meta)| {
            if let Some(meta) = function_abi.get(&meta.name) {
                traced_addresses.push(*addr);
                func_types.insert(addr, meta, 0).unwrap();
            }
        });

        Ok(Self {
            ebpf,
            traced_addresses,
        })
    }

    pub fn attach_multi(&mut self) -> anyhow::Result<()> {
        let program: &mut PerfEvent = self
            .ebpf
            .program_mut("trace_function_call")
            .unwrap()
            .try_into()
            .unwrap();
        program.load().unwrap();

        self.traced_addresses.iter().for_each(|address| {
            println!("addr: {:x}", address);
            program
                .attach(
                    PerfEventConfig::Breakpoint(BreakpointConfig::Instruction {
                        address: *address,
                    }),
                    PerfEventScope::OneProcess {
                        pid: std::process::id(),
                        cpu: None,
                    },
                    SamplePolicy::Period(1),
                    false,
                )
                .unwrap();
        });

        Ok(())
    }

    pub async fn read_events(&mut self) -> anyhow::Result<()> {
        let ring_buf = RingBuf::try_from(self.ebpf.take_map("FunctionCalls").unwrap())?;
        let mut buf =
            tokio::io::unix::AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

        tokio::task::spawn(async move {
            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                {
                    let item = guard.get_inner_mut().next().unwrap();
                    let ptr = item.as_ptr() as *const FunctionCallEvent;
                    let e = unsafe { *ptr };

                    println!("data: {:?}", e.data);

                    // let mut offset = 0;
                    // loop {
                    //     let str_len =
                    //         u32::from_le_bytes(e.data[offset..offset + 4].try_into().expect("works"));
                    //     if str_len == 0 {
                    //         break;
                    //     }
                    //     offset += 4;
                    //     let s = String::from_utf8_lossy(&e.data[offset..offset + str_len as usize]);
                    //     offset += str_len as usize;
                    //     println!("param: {s}");
                    // }
                }
                guard.clear_ready();
            }
        });

        Ok(())
    }
}
