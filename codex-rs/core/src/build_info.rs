use std::sync::OnceLock;

#[cfg(feature = "pyo3-hooks")]
use pyo3::types::PyAnyMethods;

pub fn pyo3_hooks_enabled() -> bool {
    cfg!(feature = "pyo3-hooks")
}

static PYO3_PYTHON_VERSION: OnceLock<Option<String>> = OnceLock::new();

pub fn pyo3_python_version() -> Option<String> {
    PYO3_PYTHON_VERSION
        .get_or_init(pyo3_python_version_inner)
        .clone()
}

fn pyo3_python_version_inner() -> Option<String> {
    if !pyo3_hooks_enabled() {
        return None;
    }

    #[cfg(feature = "pyo3-hooks")]
    {
        pyo3::prepare_freethreaded_python();
        pyo3::Python::with_gil(|py| {
            let sys = py.import_bound("sys")?;
            let info = sys.getattr("version_info")?;
            let major: u8 = info.getattr("major")?.extract()?;
            let minor: u8 = info.getattr("minor")?.extract()?;
            let micro: u8 = info.getattr("micro")?.extract()?;
            Ok::<_, pyo3::PyErr>(format!("{major}.{minor}.{micro}"))
        })
        .ok()
    }

    #[cfg(not(feature = "pyo3-hooks"))]
    {
        None
    }
}
