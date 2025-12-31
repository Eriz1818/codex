use dirs::home_dir;
use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

/// This was copied from codex-core but codex-core depends on this crate.
/// TODO: move this to a shared crate lower in the dependency tree.
///
///
/// Returns the path to the Codex configuration directory, which can be
/// specified by the `CODEX_HOME` environment variable. If not set, defaults to
/// `~/.codex` (or `~/.xcodex` when invoked as `xcodex`).
///
/// - If `CODEX_HOME` is set, the value will be canonicalized and this
///   function will Err if the path does not exist.
/// - If `CODEX_HOME` is not set, this function does not verify that the
///   directory exists.
pub(crate) fn find_codex_home() -> std::io::Result<PathBuf> {
    // Honor the `CODEX_HOME` environment variable when it is set to allow users
    // (and tests) to override the default location.
    if let Ok(val) = std::env::var("CODEX_HOME")
        && !val.is_empty()
    {
        return PathBuf::from(val).canonicalize();
    }

    let mut p = home_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find home directory",
        )
    })?;
    p.push(default_home_dirname());
    Ok(p)
}

const CODEX_DEFAULT_HOME_DIRNAME: &str = ".codex";
const XCODEX_DEFAULT_HOME_DIRNAME: &str = ".xcodex";
const XCODEX_EXE_STEM: &str = "xcodex";

fn is_xcodex_exe_name(name: &OsStr) -> bool {
    let Some(stem) = Path::new(name).file_stem().and_then(OsStr::to_str) else {
        return false;
    };
    stem == XCODEX_EXE_STEM
}

fn is_xcodex_invocation() -> bool {
    if let Some(argv0) = std::env::args_os().next()
        && is_xcodex_exe_name(&argv0)
    {
        return true;
    }

    if let Ok(exe) = std::env::current_exe()
        && is_xcodex_exe_name(exe.as_os_str())
    {
        return true;
    }

    false
}

fn default_home_dirname_impl(is_xcodex: bool) -> &'static str {
    if is_xcodex {
        XCODEX_DEFAULT_HOME_DIRNAME
    } else {
        CODEX_DEFAULT_HOME_DIRNAME
    }
}

fn default_home_dirname() -> &'static str {
    default_home_dirname_impl(is_xcodex_invocation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_home_dirname_switches_for_xcodex_invocation() {
        assert_eq!(CODEX_DEFAULT_HOME_DIRNAME, default_home_dirname_impl(false));
        assert_eq!(XCODEX_DEFAULT_HOME_DIRNAME, default_home_dirname_impl(true));
    }
}
