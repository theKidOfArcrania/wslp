use std::process::{self, Stdio};

use async_tempfile::TempDir;

use tokio::{
    fs,
    io::{self, AsyncBufReadExt, AsyncWriteExt},
    process::Command,
    select,
};

use crate::{error::PsError, output::Output, Result};

#[cfg(target_family = "unix")]
use crate::target::unix::PsScriptImpl;

#[cfg(target_family = "windows")]
use crate::target::windows::PsScriptImpl;

pub struct PsScript {
    pub(crate) args: Vec<&'static str>,
    pub(crate) hidden: bool,
    pub(crate) err_passthru: bool,
}

impl PsScript {
    pub async fn run(&self, script: &str) -> Result<Output> {
        let proc_output = self.run_raw(script).await?;

        let output = Output::from(proc_output);
        if output.success {
            Ok(output)
        } else {
            Err(PsError::Powershell(output))
        }
    }

    async fn run_raw(&self, script: &str) -> Result<process::Output> {
        let script_dir = TempDir::new().await?;
        let script_path = format!(
            "{}/script.ps1",
            script_dir.dir_path().as_os_str().to_string_lossy()
        );

        let mut script_file = fs::File::create_new(&script_path).await?;
        script_file.write_all(script.as_bytes()).await?;
        script_file.shutdown().await?;
        drop(script_file);

        log::info!("Writing script to {script_path}");

        let mut cmd = Command::new(PsScriptImpl::get_powershell_path()?);

        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut args_temp = self.args.clone();
        *args_temp.last_mut().expect("Should be non-empty") = &script_path;
        cmd.args(&args_temp);

        if self.hidden {
            PsScriptImpl::hide(&mut cmd);
        }

        let mut process = cmd.spawn()?;
        let mut stderr =
            io::BufReader::new(process.stderr.take().ok_or(PsError::ChildStdinNotFound)?);
        let mut stdout =
            io::BufReader::new(process.stdout.take().ok_or(PsError::ChildStdinNotFound)?);

        async fn read_line_noeof<R: AsyncBufReadExt + Unpin>(
            read: &mut R,
            buf: &mut Vec<u8>,
        ) -> io::Result<()> {
            // Try to read until we get a newline
            read.read_until(b'\n', buf).await?;

            // If we read absolutely nothing, just go into a busy loop
            if buf.is_empty() {
                std::future::pending::<()>().await;
            }
            Ok(())
        }

        let mut error = Vec::<u8>::new();
        let mut output = Vec::<u8>::new();
        let mut buf = Vec::<u8>::new();
        let mut buf2 = Vec::<u8>::new();
        let status;
        'outer: loop {
            let (log_as_error, linebuf, write_to) = select! {
                read = read_line_noeof(&mut stderr, &mut buf) => {
                    let _ = read?;
                    (self.err_passthru, &mut buf, &mut error)
                },
                read = read_line_noeof(&mut stdout, &mut buf2) => {
                    let _ = read?;
                    (false, &mut buf2, &mut output)
                },
                exit = process.wait() => {
                    status = exit?;
                    break 'outer;
                }
            };

            let line = String::from_utf8_lossy(linebuf);
            if log_as_error {
                log::error!("{line}");
            } else if let Some(("", entry)) = line.split_once("#[info]") {
                log::info!("{}", entry.trim());
            } else if let Some(("", entry)) = line.split_once("#[warn]") {
                log::warn!("{}", entry.trim());
            } else if let Some(("", entry)) = line.split_once("#[error]") {
                log::error!("{}", entry.trim());
            } else {
                write_to.append(linebuf);
            }
            linebuf.clear();
        }

        Ok(process::Output {
            status,
            stdout: output,
            stderr: error,
        })
    }
}
