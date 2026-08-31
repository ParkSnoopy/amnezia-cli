use crate::core::transaction::QuickSpec;

pub(crate) struct Adapter;

impl crate::core::transaction::sealed::Sealed for Adapter {}

impl crate::core::transaction::ProtocolAdapter for Adapter {
    const PROTOCOL: crate::core::model::Protocol = crate::core::model::Protocol::WireGuard;

    fn prepare(
        request: crate::core::transaction::PrepareRequest<'_>,
    ) -> anyhow::Result<crate::core::transaction::ProtocolRecipe> {
        crate::core::transaction::validate_quick_profile(request.source)?;
        Ok(crate::core::transaction::ProtocolRecipe::Quick(
            crate::core::transaction::QuickProgram::WireGuard,
        ))
    }
}

pub(crate) fn spec() -> QuickSpec {
    QuickSpec {
        probe_program: "wg",
        kernel_module: "wireguard",
        backend_variable: "WG_QUICK_USERSPACE_IMPLEMENTATION",
        userspace_backend: "wireguard-go",
    }
}
