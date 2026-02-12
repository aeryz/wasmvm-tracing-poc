# Wasm Tracer

This is a function tracer including the params and (possibly) the return values for JIT-compiled WASM's. The tracing is based on eBPF's and hardware interrupts so no change in the binary is needed to be able to trace the functions (assuming the function you want to trace is not inlined).

Right now, the whole repo is a proof of concept and more like a playground for me to play around with Rust eBPF. But it might turn into a cool project.
