use crate::core::runner::QuickSpec;

pub(crate) fn spec() -> QuickSpec {
    QuickSpec {
        quick_program: "awg-quick",
        probe_program: "awg",
        kernel_module: "amneziawg",
        backend_variable: "WG_QUICK_USERSPACE_IMPLEMENTATION",
        userspace_backend: "amneziawg-go",
    }
}
