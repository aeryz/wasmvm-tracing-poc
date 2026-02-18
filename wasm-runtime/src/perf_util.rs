use std::{collections::HashMap, fs};

pub struct FunctionMapping {
    addr_to_meta: HashMap<u64, FunctionMetadata>,
}

pub struct FunctionMetadata {
    /// Name of the function before mangling
    pub name: String,
    /// The full symbol that is assigned to the function
    pub symbol: String,
    /// The address of the function relative to the base memory
    /// of the JIT-compiled wasm binary
    pub addr: u64,
    /// The size of the function
    // TODO(aeryz): we might use this info to trace the ret instructions
    // need to check if cranelift jmps to end and then rets or do rets
    // at arbitrary locations tho.
    pub size: u64,
}

impl FunctionMapping {
    pub fn generate_from_perfmap_file_with_pid(bin_name: &str, pid: u32) -> wasmtime::Result<Self> {
        let mut addr_to_meta = HashMap::new();

        // TODO: make this configurable
        let data = fs::read_to_string(format!("/tmp/perf-{pid}.map"))?;

        for line in data.lines() {
            // Example: "7f3a1c400000 00000034 world"
            let mut it = line.split_whitespace();
            let addr = it.next();
            let size = it.next();
            let name = it.next();

            if let (Some(addr), Some(size), Some(name)) = (addr, size, name) {
                println!("{} {} {}", addr, size, name);
                if name.starts_with(bin_name) {
                    let addr = u64::from_str_radix(addr.trim_start_matches("0x"), 16)?;
                    let size = u64::from_str_radix(size, 16)?;

                    let maybe_name = name.split(":").last().unwrap_or(name);

                    let _ = addr_to_meta.insert(
                        addr,
                        FunctionMetadata {
                            name: maybe_name.into(),
                            symbol: name.into(),
                            addr,
                            size,
                        },
                    );
                }
            }
        }

        Ok(FunctionMapping { addr_to_meta })
    }
}

impl<'a> IntoIterator for &'a FunctionMapping {
    type Item = <&'a HashMap<u64, FunctionMetadata> as IntoIterator>::Item;

    type IntoIter = <&'a HashMap<u64, FunctionMetadata> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.addr_to_meta).into_iter()
    }
}
