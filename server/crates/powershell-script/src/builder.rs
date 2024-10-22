use std::collections::VecDeque;

use crate::psscript::PsScript;

/// Builds a `PsScript` instance with configurable options for running your
/// script.
pub struct PsScriptBuilder {
    args: VecDeque<&'static str>,
    no_profile: bool,
    non_interactive: bool,
    hidden: bool,
    err_passthru: bool,
}

impl PsScriptBuilder {
    /// Creates a default builder with no_profile, non_interactive and hidden
    /// options set to true.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn err_passthru(mut self, flag: bool) -> Self {
        self.err_passthru = flag;
        self
    }

    /// Prevents environment specifc scripts from being loaded. See [NoProfile parameter](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.2#the-noprofile-parameter)
    pub fn no_profile(mut self, flag: bool) -> Self {
        self.no_profile = flag;
        self
    }

    /// Runs the script in non-interactive mode, which does not present an
    /// interactive prompt to the user. See [NonInteractive flag](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-noninteractive)
    pub fn non_interactive(mut self, flag: bool) -> Self {
        self.non_interactive = flag;
        self
    }

    /// Prevents PowerShell window from being shown by creating a console
    /// window with the CREATE_NO_WINDOW flag set. See [creation flags](https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
    ///
    /// ## Note
    /// On any other platform than Windows this is currently a no-op.
    pub fn hidden(mut self, flag: bool) -> Self {
        self.hidden = flag;
        self
    }

    pub fn build(self) -> PsScript {
        let mut args = self.args;
        if self.non_interactive {
            args.push_front("-NonInteractive");
        }

        if self.no_profile {
            args.push_front("-NoProfile");
        }

        PsScript {
            args: args.make_contiguous().to_vec(),
            hidden: self.hidden,
            err_passthru: self.err_passthru,
        }
    }
}

impl Default for PsScriptBuilder {
    /// Creates a default builder with `no_profile`, `non_interactive` and `hidden`
    /// options set to `true`.
    fn default() -> Self {
        let mut args = VecDeque::new();
        args.push_back("-Execution");
        args.push_back("Unrestricted");
        args.push_back("-");

        Self {
            args,
            no_profile: true,
            non_interactive: true,
            hidden: true,
            err_passthru: false,
        }
    }
}
