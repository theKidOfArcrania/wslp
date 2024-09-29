use std::{collections::BTreeMap, fmt::Display, marker::PhantomData, sync::OnceLock};

use anyhow::bail;
use powershell_script::{Output, PsScript, PsScriptBuilder};
use tokio::fs;

use crate::wmi_ext;

macro_rules! cenum {
    ($(enum $name:ident { $($memb:ident),*$(,)?} )*) => {
        $(#[derive(Debug)]
        #[allow(unused)]
        pub enum $name {
            $($memb),*
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", match self {
                    $(Self::$memb => stringify!($memb)),*
                })
            }
        })*
    }
}

pub fn create_ps() -> PsScript {
    PsScriptBuilder::new()
        .non_interactive(false)
        .no_profile(true)
        .print_commands(false)
        .build()
}

pub enum Generation {
    Gen1,
    Gen2,
}

#[derive(Default)]
pub enum VhdSpec {
    Existing {
        path: String,
    },
    New {
        path: String,
        size: String,
    },
    #[default]
    None,
}

#[allow(unused)]
#[derive(Debug)]
pub enum BootDevice {
    CD,
    Floppy,
    LegacyNetworkAdapter,
    IDE,
    NetworkAdapter,
    VHD,
}

#[derive(Default)]
pub struct VmBuilder {
    backing_path: Option<String>,
    name: Option<String>,
    gen: Option<Generation>,
    boot_device: Option<BootDevice>,
    memory_startup_bytes: Option<String>,
    vhd: VhdSpec,
    path: Option<String>,
}

impl VmBuilder {
    pub fn backing_path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    pub fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    #[allow(unused)]
    pub fn use_gen1(mut self) -> Self {
        self.gen = Some(Generation::Gen1);
        self
    }

    pub fn use_gen2(mut self) -> Self {
        self.gen = Some(Generation::Gen2);
        self
    }

    pub fn boot_device(mut self, dev: BootDevice) -> Self {
        self.boot_device = Some(dev);
        self
    }

    pub fn memory_startup_bytes(mut self, size: String) -> Self {
        self.memory_startup_bytes = Some(size);
        self
    }

    #[allow(unused)]
    pub fn no_vhd(mut self) -> Self {
        self.vhd = VhdSpec::None;
        self
    }

    #[allow(unused)]
    pub fn new_vhd(mut self, path: String, size: String) -> Self {
        self.vhd = VhdSpec::New { path, size };
        self
    }

    pub fn existing_vhd(mut self, path: String) -> Self {
        self.vhd = VhdSpec::Existing { path };
        self
    }

    pub fn path(mut self, path: String) -> Self {
        self.path = Some(path);
        self
    }

    pub async fn build(self) -> anyhow::Result<Vm> {
        let mut args = Vec::new();
        let name = self.name.unwrap_or_else(|| "New Virtual Machine".into());

        args.push("-Name".into());
        args.push(name.clone());

        if let Some(boot_device) = self.boot_device {
            args.push("-BootDevice".into());
            args.push(format!("{boot_device:?}"));
        }

        match self.vhd {
            VhdSpec::Existing { path } => {
                args.push("-VHDPath".into());
                args.push(path);
            }
            VhdSpec::New { path, size } => {
                args.push("-NewVHDPath".into());
                args.push(path);
                args.push("-NewVHDSizeBytes".into());
                args.push(size);
            }
            VhdSpec::None => args.push("-NoVHD".into()),
        }

        if let Some(path) = self.path {
            args.push("-Path".into());
            args.push(path);
        }

        if let Some(memory_startup_bytes) = self.memory_startup_bytes {
            args.push("-MemoryStartupBytes".into());
            args.push(memory_startup_bytes);
        }

        Vm::new(self.backing_path, name, args).await
    }
}

pub struct Vm {
    backing_path: Option<String>,
    vm_wmi_path: OnceLock<String>,
    ps: PsScript,
    name: String,
}

impl Clone for Vm {
    fn clone(&self) -> Self {
        Self {
            backing_path: self.backing_path.clone(),
            vm_wmi_path: OnceLock::new(),
            ps: create_ps(),
            name: self.name.clone(),
        }
    }
}

pub(crate) async fn run_cmd(ps: &PsScript, cmd: &str, args: Vec<String>) -> anyhow::Result<Output> {
    let mut script: String = cmd.into();
    for arg in args {
        script.push_str(" ");

        let mut tmp = String::new();
        let mut need_quotes = false;
        for c in arg.chars() {
            let repl = match c {
                ' ' => {
                    need_quotes = true;
                    None
                }
                '"' => Some("`\""),
                '$' => Some("`$"),
                '`' => Some("``"),
                _ => None,
            };
            match repl {
                None => tmp.push(c),
                Some(repl) => {
                    need_quotes = true;
                    tmp.push_str(repl);
                }
            }
        }

        if need_quotes {
            script.push_str(&format!("\"{tmp}\""))
        } else {
            script.push_str(&arg);
        }
    }
    Ok(ps.run(&script).await?)
}

impl Vm {
    pub async fn new(
        backing_path: Option<String>,
        name: String,
        args: Vec<String>,
    ) -> anyhow::Result<Self> {
        let ps = create_ps();
        let _ = run_cmd(&ps, "New-VM", args).await?;
        Ok(Self {
            vm_wmi_path: OnceLock::new(),
            backing_path,
            ps,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_bundled<'v>(&'v self) -> VMSetBuilder<'v> {
        VMSetBuilder {
            vm: self,
            args: BTreeMap::new(),
        }
    }

    pub fn get_wmi_path(&self) -> anyhow::Result<&str> {
        self.vm_wmi_path
            .get_or_try_init(|| {
                let conn = wmi_ext::get_connection()?;
                for vm in conn.exec_query_native_wrapper("select * from Msvm_ComputerSystem")? {
                    let vm: wmi_ext::ComputerSystem = vm?.into_desr()?;
                    if vm.element_name == self.name {
                        return Ok(vm.wmi_path);
                    }
                }

                bail!("Unable to find VM '{}' in wmi interface!", self.name)
            })
            .map(|s| s.as_str())
    }

    pub fn get_keyboard(&self) -> anyhow::Result<Option<wmi_ext::Keyboard>> {
        let path = self.get_wmi_path()?;
        let conn = wmi_ext::get_connection()?;
        Ok(
            conn.associators::<wmi_ext::Keyboard, wmi_ext::SystemDevice>(path)?
                .into_iter()
                .next()
        )
    }

    pub fn try_get_keyboard(&self) -> anyhow::Result<wmi_ext::Keyboard> {
        self.get_keyboard()?
            .ok_or_else(|| wmi::WMIError::ResultEmpty.into())
    }

    pub async fn add_network(&self, switch: String) -> anyhow::Result<()> {
        run_cmd(
            &self.ps,
            "Add-VMNetworkAdapter",
            vec![
                "-VmName".into(),
                self.name.clone(),
                "-SwitchName".into(),
                switch,
            ],
        )
        .await?;
        Ok(())
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        run_cmd(
            &self.ps,
            "Start-VM",
            vec!["-VmName".into(), self.name.clone()],
        )
        .await?;
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        run_cmd(
            &self.ps,
            "Stop-VM",
            vec!["-VmName".into(), self.name.clone(), "-Force".into()],
        )
        .await?;
        Ok(())
    }

    pub async fn cleanup(self) -> anyhow::Result<()> {
        let res = self.stop().await;
        // TODO: Delete VM
        if let Some(path) = self.backing_path {
            fs::remove_dir_all(path).await?;
        }
        res
    }

    #[allow(unused)]
    pub async fn set<T: Display>(
        &self,
        attr: &VmAttributeTemplate<T>,
        val: T,
    ) -> anyhow::Result<()> {
        self.set_bundled().set(attr, val).commit().await
    }
}

pub struct VmAttributeTemplate<A> {
    name: &'static str,
    group: &'static str,
    _pdata: PhantomData<*const A>,
}

impl<A: Display> VmAttributeTemplate<A> {
    const fn new(name: &'static str, group: &'static str) -> Self {
        Self {
            name,
            group,
            _pdata: PhantomData,
        }
    }
}

cenum! {
    enum StartAction {
        Nothing,
        StartIfRunning,
        Start,
    }

    enum StopAction {
        TurnOff,
        Save,
        Shutdown,
    }

    enum PSState {
        On, Off
    }
}

pub struct PSBool(pub bool);
impl Display for PSBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "${}", self.0)
    }
}

pub mod attrs {
    use super::*;

    macro_rules! attr {
        ($($group: ident { $($name:ident: $tp:ty),* $(,)? })*) => {
            $($(
                #[allow(non_upper_case_globals)]
                pub const $name: VmAttributeTemplate::<$tp> =
                VmAttributeTemplate::<$tp>::new(stringify!($name), stringify!($group));
            )*)*
        }
    }

    attr! {
        VM {
            AutomaticStartAction: StartAction,
            AutomaticStopAction: StopAction,
            AutomaticCheckpointsEnabled: PSBool,
            ProcessorCount: u32,
        }
        VMProcessor {
            ExposeVirtualizationExtensions: PSBool,
        }
        VMFirmware {
            EnableSecureBoot: PSState,
        }
    }
}

pub struct VMSetBuilder<'v> {
    vm: &'v Vm,
    args: BTreeMap<String, Vec<String>>,
}

impl<'v> VMSetBuilder<'v> {
    pub fn set<T: Display>(mut self, attr: &VmAttributeTemplate<T>, val: T) -> Self {
        let args = self
            .args
            .entry(attr.group.to_string())
            .or_insert_with(|| vec!["-VMName".into(), self.vm.name.clone()]);
        args.push(format!("-{}", attr.name));
        args.push(val.to_string());
        self
    }

    pub async fn commit(self) -> anyhow::Result<()> {
        for (group, args) in self.args {
            run_cmd(&self.vm.ps, &format!("Set-{group}"), args).await?;
        }
        Ok(())
    }
}
