use std::{cell::RefCell, collections::HashMap, mem::transmute, rc::Rc};

use serde::Deserialize;
use windows::{core::{w, IUnknown, BSTR, HSTRING, VARIANT}, Win32::System::{Variant as var, Wmi::IWbemClassObject}};
use wmi::{result_enumerator::IWbemClassWrapper, variant::IUnknownWrapper};

thread_local! {
    static CONNECTION: RefCell<Option<Rc<wmi::WMIConnection>>> = RefCell::new(None);
}

pub fn get_connection() -> wmi::WMIResult<Rc<wmi::WMIConnection>> {
    CONNECTION.with_borrow_mut(|conn| {
        Ok(match conn {
            conn @ None => conn
                .insert(Rc::new(wmi::WMIConnection::with_namespace_path(
                    "root\\virtualization\\v2",
                    wmi::COMLibrary::new()?,
                )?))
                .clone(),
            Some(conn) => conn.clone(),
        })
    })
}

unsafe fn to_variant(variant: &wmi::Variant) -> VARIANT {
    match variant {
        wmi::Variant::Empty => var::VariantInit(),
        wmi::Variant::Null => todo!(), // See https://github.com/microsoft/windows-rs/issues/2983
        wmi::Variant::String(st) => VARIANT::from(st.as_str()),
        wmi::Variant::I1(val) => VARIANT::from(*val),
        wmi::Variant::I2(val) => VARIANT::from(*val),
        wmi::Variant::I4(val) => VARIANT::from(*val),
        wmi::Variant::I8(val) => VARIANT::from(*val),
        wmi::Variant::UI1(val) => VARIANT::from(*val),
        wmi::Variant::UI2(val) => VARIANT::from(*val),
        wmi::Variant::UI4(val) => VARIANT::from(*val),
        wmi::Variant::UI8(val) => VARIANT::from(*val),
        wmi::Variant::R4(val) => VARIANT::from(*val),
        wmi::Variant::R8(val) => VARIANT::from(*val),
        wmi::Variant::Bool(val) => VARIANT::from(*val),
        wmi::Variant::Array(_) => todo!(),
        wmi::Variant::Unknown(unk) => VARIANT::from(unsafe {
            // SAFETY: this is transmuting a transparent wrapper around IUnknown
            transmute::<&IUnknownWrapper, &IUnknown>(unk).clone()
        }),
        wmi::Variant::Object(obj) => VARIANT::from(unsafe {
            // SAFETY: this is transmuting a transparent wrapper around IUnknown
            transmute::<IWbemClassObject, IUnknown>(obj.inner.clone()).clone()
        }),
    }
}

trait IWbemClassExt {
    fn invoke_inst_method_raw(
        &self,
        conn: &wmi::WMIConnection,
        name: &str,
        args: &HashMap<String, wmi::Variant>,
    ) -> wmi::WMIResult<wmi::Variant>;
}

impl IWbemClassExt for IWbemClassWrapper {
    fn invoke_inst_method_raw(
        &self,
        conn: &wmi::WMIConnection,
        method: &str,
        args: &HashMap<String, wmi::Variant>,
    ) -> wmi::WMIResult<wmi::Variant> {
        let mut input = None;
        let path = self.path()?;
        let class = self.class()?;
        unsafe {
            let mut classobj = None;
            conn.svc.GetObject(
                &BSTR::from(class.as_str()),
                Default::default(),
                None,
                Some(&mut classobj),
                None,
            )?;
            let classobj = classobj.unwrap();
            classobj.GetMethod(
                &HSTRING::from(method),
                0,
                &mut input,
                std::ptr::null_mut(),
            )?;

            let mut output = None;
            match input {
                None => {
                    conn.svc.ExecMethod(
                        &BSTR::from(path),
                        &BSTR::from(method),
                        Default::default(),
                        None,
                        None,
                        Some(&mut output),
                        None
                    )?;
                }
                Some(inputclass) => {
                    let params = inputclass.SpawnInstance(0)?;
                    for (name, value) in args {
                        params.Put(
                            &HSTRING::from(name),
                            0,
                            &to_variant(value),
                            0,
                        )?;
                    }

                    conn.svc.ExecMethod(
                        &BSTR::from(path),
                        &BSTR::from(method),
                        Default::default(),
                        None,
                        &params,
                        Some(&mut output),
                        None
                    )?;
                }
            }

            let output = output.unwrap();
            let mut value = VARIANT::default();
            output.Get(w!("ReturnValue"), 0, &mut value, None, None)?;
            wmi::Variant::from_variant(&value)
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Msvm_SystemDevice")]
pub struct SystemDevice {}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[serde(rename = "Msvm_ComputerSystem")]
pub struct ComputerSystem {
    #[serde(rename = "__Path")]
    pub wmi_path: String,
    pub caption: String,
    pub description: String,
    pub element_name: String,
    pub install_date: Option<wmi::WMIDateTime>,
    pub operational_status: Vec<u16>,
    pub status_descriptions: Vec<String>,
    pub status: String,
    pub health_state: u16,
    pub enabled_state: u16,
    pub other_enabled_state: Option<String>,
    pub requested_state: u16,
    pub time_of_last_state_change: Option<wmi::WMIDateTime>,
    pub name: String,
    pub primary_owner_name: Option<String>,
    pub primary_owner_contact: Option<String>,
    pub identifying_descriptions: Vec<String>,
    pub other_identifying_info: Vec<String>,
    pub dedicated: Vec<u16>,
    pub other_dedicated_descriptions: Vec<String>,
    pub reset_capability: u16,
    pub power_management_capabilities: Vec<u16>,
    pub enabled_default: u16,
    pub creation_class_name: String,
    pub roles: Vec<String>,
    pub name_format: Option<String>,
    pub on_time_in_milliseconds: Option<u64>,
    pub time_of_last_configuration_change: Option<wmi::WMIDateTime>,
    #[serde(rename = "ProcessID")]
    pub process_id: Option<u32>,
    //pub assigned_numa_node_list: Vec<u16>,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Msvm_VirtualSystemManagementService")]
pub struct VirtualSystemManagementService {
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[serde(rename = "Msvm_Keyboard")]
pub struct Keyboard {
    #[serde(skip)]
    raw: RefCell<Option<IWbemClassWrapper>>,
    #[serde(rename = "__Path")]
    pub wmi_path: String,
}

impl Keyboard {
    fn raw(&self, conn: &wmi::WMIConnection) -> anyhow::Result<IWbemClassWrapper> {
        if let Some(raw) = (*self.raw.borrow()).clone() {
            return Ok(raw.clone());
        }

        let raw = conn.get_raw_by_path(&self.wmi_path)?;
        *self.raw.borrow_mut() = Some(raw.clone());
        Ok(raw)
    }

    pub fn type_ctrl_alt_del(&self, conn: &wmi::WMIConnection) -> anyhow::Result<i32> {
        let raw = self.raw(conn)?;
        let args = HashMap::new();
        let res = raw.invoke_inst_method_raw(conn, "TypeCtrlAltDel", &args)?;
        Ok(res.try_into()?)
    }

    pub fn press_key(&self, conn: &wmi::WMIConnection, keycode: u32) -> anyhow::Result<i32> {
        let raw = self.raw(conn)?;
        let mut args = HashMap::new();
        args.insert("keyCode".into(), wmi::Variant::I4(keycode as i32));
        let res = raw.invoke_inst_method_raw(conn, "PressKey", &args)?;
        Ok(res.try_into()?)
    }

    pub fn type_key(&self, conn: &wmi::WMIConnection, keycode: u32) -> anyhow::Result<i32> {
        let raw = self.raw(conn)?;
        let mut args = HashMap::new();
        args.insert("keyCode".into(), wmi::Variant::I4(keycode as i32));
        let res = raw.invoke_inst_method_raw(conn, "TypeKey", &args)?;
        Ok(res.try_into()?)
    }

    pub fn type_text(&self, conn: &wmi::WMIConnection, text: String) -> anyhow::Result<i32> {
        let raw = self.raw(conn)?;
        let mut args = HashMap::new();
        args.insert("asciiText".into(), wmi::Variant::String(text));
        let res = raw.invoke_inst_method_raw(conn, "TypeText", &args)?;
        Ok(res.try_into()?)
    }
}
