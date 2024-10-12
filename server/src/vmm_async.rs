use cgmath::{InnerSpace, MetricSpace, Vector2, Vector3, Zero};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex as SMutex,
    },
};
use tokio::{
    sync::Notify,
    task::{spawn_blocking, JoinHandle},
    time,
};

use crate::{sess, utils, vmm, wmi_ext};

const COLOR_LOGIN_FIELD: Vector3<f32> = Vector3::new(0.094, 0.11, 0.22);
const COLOR_TASKBAR: Vector3<f32> = Vector3::new(0.91, 0.925, 0.91);
const COLOR_WINRUN: Vector3<f32> = Vector3::new(0.941, 0.941, 0.941);

const LOGIN_X: usize = 50;
const LOGIN_Y: usize = 34;
const LOGIN_SZ: usize = 2;
const LOGIN_FIELD_X: usize = 50;
const LOGIN_FIELD_Y: usize = 54;
const TASKBAR_TOP: usize = 83;
const TASKBAR_BOT: usize = 87;
const TASKBAR_X: usize = 20;
const TASKBAR_W: usize = 5;
const WINRUN_X: usize = 8;
const WINRUN_Y: usize = 63;

fn snapshot(vssd_path: &str, width: i16, height: i16) -> anyhow::Result<Option<Vec<Vector3<f32>>>> {
    const FRAC: f32 = 1.0 / 256.0;

    let vsm = wmi_ext::VirtualSystemManagementService::singleton()?;
    let vssd = wmi_ext::VirtualSystemSettingData::new(vssd_path.into());
    let data = vsm.get_virtual_system_thumbnail_image(&vssd, width, height)?;
    if data.len() == 0 {
        return Ok(None);
    }

    let mut ret = Vec::new();
    let data = bytemuck::cast_slice::<_, u16>(&data[4..]);
    for &pixel in data {
        let b = (pixel << 3) as u8 as f32 * FRAC;
        let g = ((pixel >> 3) & !3) as u8 as f32 * FRAC;
        let r = ((pixel >> 8) & !7) as u8 as f32 * FRAC;
        ret.push(Vector3::new(r, g, b));
    }

    Ok(Some(ret))
}

/*
fn save_screenshot(vssd_path: &str, file: &str, width: i16, height: i16) -> anyhow::Result<()> {
    let idata = snapshot(vssd_path, width, height)?;
    if let Some(idata) = idata {
        let idata: Vec<_> = idata.into_iter().flat_map(|mut v| {
            v = v * 256.0;
            [v.x as u8, v.y as u8, v.z as u8]
        }).collect();
        let file = std::fs::File::create(file)?;
        let mut img = png::Encoder::new(file, width.try_into()?, height.try_into()?);
        img.set_color(png::ColorType::Rgb);
        img.set_depth(png::BitDepth::Eight);
        let mut writer = img.write_header()?;
        writer.write_image_data(&idata)?;
        writer.finish()?;
    }
    Ok(())
}
*/

fn region_color(
    vssd_path: &str,
    width: i16,
    height: i16,
    top: Vector2<usize>,
    size: Vector2<usize>,
) -> anyhow::Result<Option<Vector3<f32>>> {
    let data = snapshot(&vssd_path, width, height)?;
    Ok(if let Some(pixels) = data {
        let mut sum = Vector3::zero();
        let mut cnt = 0;
        for x in top.x..(top.x + size.x) {
            for y in top.y..(top.y + size.y) {
                sum += pixels[y * width as usize + x];
                cnt += 1;
            }
        }
        Some(sum / cnt as f32)
    } else {
        None
    })
}

fn color_matches(actual_color: Option<Vector3<f32>>, target_color_set: &[Vector3<f32>]) -> bool {
    let Some(color) = actual_color else {
        return false;
    };
    for target_color in target_color_set {
        if target_color.distance2(color) < 0.0001 {
            return true;
        }
    }
    false
}

#[derive(Debug)]
pub enum KeyboardJobType {
    TypeCtrlAltDel(),
    TypeText(String),
    PressKey(u32),
    ReleaseKey(u32),
    //TypeKey(u32),
}

struct KeyboardJob {
    tp: KeyboardJobType,
    notify: Notify,
}

impl KeyboardJob {
    fn new(tp: KeyboardJobType) -> Arc<Self> {
        Arc::new(Self {
            tp,
            notify: Notify::new(),
        })
    }
}

#[derive(Default)]
struct KeyboardJobState {
    running_notify: Notify,
    stopping: AtomicBool,
    jobs: SMutex<VecDeque<Arc<KeyboardJob>>>,
    job_notify: Condvar,
}

pub struct KeyboardJobSet {
    join: utils::SharedFuture<JoinHandle<anyhow::Result<()>>>,
    state: Arc<KeyboardJobState>,
}

macro_rules! keyjob {
    ($($fn:ident($($arg:ident: $tp:ty)*) -> $enum:ident;)*) => {
        $(
            pub async fn $fn(&self $(, $arg: $tp)*) -> anyhow::Result<()> {
                self.submit_job(KeyboardJobType::$enum($($arg)*)).await
            }
        )*
    }
}

impl Drop for KeyboardJobSet {
    fn drop(&mut self) {
        self.state.stopping.store(true, Ordering::Relaxed);
        self.state.job_notify.notify_one();
    }
}

impl KeyboardJobSet {
    pub async fn new(vm: &vmm::Vm) -> anyhow::Result<Self> {
        let vm = vm.clone();
        let state = Arc::new(KeyboardJobState::default());

        let state2 = state.clone();
        let join = spawn_blocking(move || {
            let kb = vm.try_get_keyboard()?;
            state2.running_notify.notify_one();
            while !state2.stopping.load(Ordering::Relaxed) {
                let mut state_lock = state2.jobs.lock().unwrap();
                let job = match state_lock.pop_front() {
                    Some(job) => {
                        drop(state_lock);
                        job
                    }
                    None => {
                        let res = state2.job_notify.wait(state_lock).unwrap().pop_front();
                        match res {
                            Some(job) if !state2.stopping.load(Ordering::Relaxed) => job,
                            _ => continue,
                        }
                    }
                };

                log::debug!("VM {}: Performing keyboard job: {:?}", vm.name(), job.tp);
                let _ = match &job.tp {
                    KeyboardJobType::TypeCtrlAltDel() => kb.type_ctrl_alt_del(),
                    KeyboardJobType::TypeText(msg) => kb.type_text(msg.clone()),
                    &KeyboardJobType::PressKey(kc) => kb.press_key(kc),
                    &KeyboardJobType::ReleaseKey(kc) => kb.release_key(kc),
                    //&KeyboardJobType::TypeKey(kc) => kb.type_key(kc),
                }?;

                job.notify.notify_one();
            }
            Ok(())
        });

        let join = utils::SharedFuture::new(join);
        let join2 = join.clone();
        tokio::select! {
            _ = state.running_notify.notified() => { () }
            joinres = join2.get() => {
                joinres??;
                anyhow::bail!("Job has already been aborted");
            }
        };

        Ok(Self { state, join })
    }

    pub async fn submit_job(&self, job: KeyboardJobType) -> anyhow::Result<()> {
        let job = KeyboardJob::new(job);
        let join = self.join.clone();
        log::debug!("Submitting keyboard job: {:?}", job.tp);
        self.state.jobs.lock().unwrap().push_back(job.clone());
        self.state.job_notify.notify_one();
        tokio::select! {
            _ = job.notify.notified() => { () }
            joinres = join.get() => {
                joinres??;
                anyhow::bail!("Job has already been aborted");
            }
        };
        Ok(())
    }

    keyjob! {
        type_ctrl_alt_del() -> TypeCtrlAltDel;
        type_text(msg: String) -> TypeText;
        press_key(kc: u32) -> PressKey;
        release_key(kc: u32) -> ReleaseKey;
        //type_key(kc: u32) -> TypeKey;
    }

    pub async fn stop(self) -> anyhow::Result<()> {
        self.state.stopping.store(true, Ordering::Relaxed);
        self.state.job_notify.notify_one();
        self.join.get().await?
    }
}

impl vmm::Vm {
    pub async fn wait_for_region(
        &self,
        top: Vector2<usize>,
        size: Vector2<usize>,
        target: Vector3<f32>,
    ) -> anyhow::Result<()> {
        self.wait_for_region_set(top, size, vec![target]).await
    }

    pub async fn wait_for_region_set(
        &self,
        top: Vector2<usize>,
        size: Vector2<usize>,
        targets: Vec<Vector3<f32>>,
    ) -> anyhow::Result<()> {
        loop {
            let color = region_color(self.get_vssd_path()?, 100, 100, top, size)?;
            if color_matches(color, &targets) {
                return Ok(());
            }

            time::sleep(time::Duration::from_secs_f32(0.1)).await;
        }
    }

    pub async fn get_keyboard_async(&self) -> anyhow::Result<KeyboardJobSet> {
        KeyboardJobSet::new(self).await
    }

    pub async fn wait_for_login(&self) -> anyhow::Result<()> {
        let kb = self.get_keyboard_async().await?;
        loop {
            kb.press_key(0x0b).await?; // VK_CONTROL

            let color = region_color(
                self.get_vssd_path()?,
                100,
                100,
                Vector2::new(LOGIN_X, LOGIN_Y),
                Vector2::new(LOGIN_SZ, LOGIN_SZ),
            )?;
            if let Some(color) = color {
                if color.magnitude() > 0.7 {
                    break;
                }
            }

            time::sleep(time::Duration::from_secs_f32(0.5)).await;
        }
        kb.stop().await?;
        Ok(())
    }

    pub async fn input_credentials(&self, pwd: &str) -> anyhow::Result<()> {
        let kb = self.get_keyboard_async().await?;
        kb.type_ctrl_alt_del().await?;

        log::info!("VM {}: Waiting for login field to load", self.name());
        self.wait_for_region(
            Vector2::new(LOGIN_FIELD_X, LOGIN_FIELD_Y),
            Vector2::new(1, 1),
            COLOR_LOGIN_FIELD,
        )
        .await?;

        kb.type_text(format!("{pwd}\n")).await?;
        kb.stop().await?;

        log::info!("VM {}: Waiting for taskbar to load", self.name());
        self.wait_for_region(
            Vector2::new(TASKBAR_X, TASKBAR_TOP),
            Vector2::new(TASKBAR_W, TASKBAR_BOT - TASKBAR_TOP),
            COLOR_TASKBAR,
        )
        .await?;

        Ok(())
    }

    pub async fn start_wsl(&self, conn: &sess::MultiplexAddr) -> anyhow::Result<()> {
        let kb = self.get_keyboard_async().await?;

        log::info!("VM {}: Launching runner", self.name());
        kb.press_key(0x5B).await?; // VK_LWIN
        kb.press_key(0x52).await?; // R
        time::sleep(time::Duration::from_secs(3)).await;

        kb.release_key(0x5B).await?; // VK_LWIN
        kb.release_key(0x52).await?; // R

        self.wait_for_region(
            Vector2::new(WINRUN_X, WINRUN_Y),
            Vector2::new(1, 1),
            COLOR_WINRUN,
        )
        .await?;

        log::info!("VM {}: Launching debian", self.name());
        kb.type_text(format!("debian run /home/ctf/runner {conn}"))
            .await?;

        time::sleep(time::Duration::from_secs(3)).await;
        kb.press_key(0xD).await?; // VK_RETURN
        kb.stop().await?;

        Ok(())
    }
}
