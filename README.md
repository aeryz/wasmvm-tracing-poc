# Wasm Tracer

This is a function tracer including the params and (possibly) the return values for JIT-compiled WASM's. The tracing is based on eBPF's and hardware interrupts so it can only trace up to 4 function calls per CPU.

Hardware breakpoints for this purpose is not useful for the real stuff because of how limited it is, but at least it's cool.
