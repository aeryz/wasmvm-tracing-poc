use std::{fs, marker::PhantomData, path::Path};

use anyhow::anyhow;
use wasmtime::{
    Config, Engine, Instance, Linker, Module, ProfilingStrategy, Store, WasmParams, WasmResults,
};

pub trait WasmVM {
    const ALLOC_FN_NAME: &str;
    const MEMORY_NAME: &str;

    type Data: 'static;
}

pub struct WasmRunner<VM: WasmVM> {
    pub module: Module,
    pub linker: Linker<VM::Data>,
    pub engine: Engine,
    pub store: Store<VM::Data>,
    pub instance: Instance,
    _marker: PhantomData<VM>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct WasmSlice {
    pub ptr: u32,
    pub len: u32,
}

impl<VM: WasmVM> WasmRunner<VM> {
    pub fn load<P: AsRef<Path>>(path: P, data: VM::Data) -> anyhow::Result<Self> {
        let mut config = Config::new();
        config.profiler(ProfilingStrategy::PerfMap);

        let engine = Engine::new(&config)?;

        let module = Module::new(&engine, fs::read(path)?)?;

        let linker = Linker::new(&engine);

        let mut store = Store::new(&engine, data);

        let instance = linker.instantiate(&mut store, &module)?;

        Ok(WasmRunner {
            module,
            linker,
            engine,
            store,
            instance,
            _marker: PhantomData,
        })
    }

    pub fn allocate(&mut self, size: u32) -> anyhow::Result<u32> {
        Ok(self
            .instance
            .get_typed_func::<u32, u32>(&mut self.store, VM::ALLOC_FN_NAME)?
            .call(&mut self.store, size)?)
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<WasmSlice> {
        let ptr = self.allocate(bytes.len() as u32)?;

        let memory = self
            .instance
            .get_memory(&mut self.store, VM::MEMORY_NAME)
            .ok_or(anyhow!("could not find the memory"))?;

        let data = memory.data_mut(&mut self.store);
        let start = ptr as usize;
        let end = start + bytes.len();
        if end > data.len() {
            panic!("too small")
        }
        data[start..end].copy_from_slice(bytes);

        Ok(WasmSlice {
            ptr,
            len: bytes.len() as u32,
        })
    }

    pub fn get_memory_base(&mut self) -> anyhow::Result<u64> {
        let memory = self
            .instance
            .get_memory(&mut self.store, VM::MEMORY_NAME)
            .ok_or(anyhow!("could not find the memory"))?;

        Ok(memory.data_ptr(&self.store) as u64)
    }
}
