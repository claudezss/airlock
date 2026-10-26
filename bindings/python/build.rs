fn main() {
    // Lets `cargo build --workspace` link the extension on macOS, where
    // Python symbols are resolved at import time. maturin does this itself.
    pyo3_build_config::add_extension_module_link_args();
}
