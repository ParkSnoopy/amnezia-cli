use crate::core::runner::QuickSpec;

pub(crate) fn spec() -> QuickSpec {
    QuickSpec {
        quick_program: "wg-quick",
        probe_program: "wg",
        kernel_module: "wireguard",
        backend_variable: "WG_QUICK_USERSPACE_IMPLEMENTATION",
        userspace_backend: "wireguard-go",
    }
}
