use crate::core::transaction::QuickSpec;

pub(crate) struct Adapter;

impl crate::core::transaction::sealed::Sealed for Adapter {}

impl crate::core::transaction::ProtocolAdapter for Adapter {
    const PROTOCOL: crate::core::model::Protocol = crate::core::model::Protocol::AmneziaWg;

    fn prepare(
        request: crate::core::transaction::PrepareRequest<'_>,
    ) -> anyhow::Result<crate::core::transaction::ProtocolRecipe> {
        crate::core::transaction::validate_quick_profile(request.source)?;
        Ok(crate::core::transaction::ProtocolRecipe::Quick(
            crate::core::transaction::QuickProgram::AmneziaWg,
        ))
    }
}

pub(crate) fn spec() -> QuickSpec {
    QuickSpec {
        probe_program: "awg",
        kernel_module: "amneziawg",
        backend_variable: "WG_QUICK_USERSPACE_IMPLEMENTATION",
        userspace_backend: "amneziawg-go",
    }
}
