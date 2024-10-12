#![feature(strict_overflow_ops)]
#![feature(slice_split_once)]
#![feature(const_option)]
#![feature(io_error_more)]

use clap::Parser;
use dokan::{
    init, shutdown, unmount, CreateFileInfo, DiskSpaceInfo, FileInfo, FileSystemHandler,
    FileSystemMounter, FileTimeOperation, FillDataError, FindData, MountFlags, MountOptions,
    OperationInfo, OperationResult, VolumeInfo, IO_SECURITY_CONTEXT,
};
use dokan_sys::win32::{
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_MAXIMUM_DISPOSITION, FILE_OPEN,
    FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE,
};
use fs2::FileExt;
use std::{
    collections::HashMap,
    fs::{File, FileTimes},
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::FileTimesExt,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::SystemTime,
};
use tempfile::NamedTempFile;
use widestring::{U16CStr, U16CString, U16Str};
use winapi::{shared::ntstatus, um::winnt};

const MAX_COMPONENT_LENGTH: u32 = 255;

mod delta;

fn to_ntstatus(value: io::Error) -> i32 {
    match value.kind() {
        io::ErrorKind::NotFound => ntstatus::STATUS_OBJECT_NAME_NOT_FOUND,
        io::ErrorKind::PermissionDenied => ntstatus::STATUS_ACCESS_DENIED,
        io::ErrorKind::BrokenPipe => ntstatus::STATUS_PIPE_BROKEN,
        io::ErrorKind::AlreadyExists => ntstatus::STATUS_OBJECT_NAME_EXISTS,
        io::ErrorKind::NotADirectory => ntstatus::STATUS_NOT_A_DIRECTORY,
        io::ErrorKind::IsADirectory => ntstatus::STATUS_FILE_IS_A_DIRECTORY,
        io::ErrorKind::DirectoryNotEmpty => ntstatus::STATUS_DIRECTORY_NOT_EMPTY,
        io::ErrorKind::InvalidInput => ntstatus::STATUS_INVALID_PARAMETER,
        io::ErrorKind::InvalidData => ntstatus::STATUS_INVALID_PARAMETER,
        io::ErrorKind::TimedOut => ntstatus::STATUS_TIMEOUT,
        io::ErrorKind::StorageFull => ntstatus::STATUS_DISK_FULL,
        io::ErrorKind::NotSeekable => ntstatus::STATUS_INVALID_PARAMETER,
        io::ErrorKind::FilesystemQuotaExceeded => ntstatus::STATUS_DISK_FULL,
        io::ErrorKind::FileTooLarge => ntstatus::STATUS_FILE_TOO_LARGE,
        io::ErrorKind::ResourceBusy => ntstatus::STATUS_DEVICE_BUSY,
        io::ErrorKind::ExecutableFileBusy => ntstatus::STATUS_DEVICE_BUSY,
        io::ErrorKind::Deadlock => ntstatus::STATUS_DEVICE_BUSY,
        io::ErrorKind::TooManyLinks => ntstatus::STATUS_TOO_MANY_LINKS,
        io::ErrorKind::InvalidFilename => ntstatus::STATUS_NAME_TOO_LONG,
        io::ErrorKind::ArgumentListTooLong => ntstatus::STATUS_NAME_TOO_LONG,
        io::ErrorKind::Interrupted => ntstatus::STATUS_IO_PREEMPTED,
        io::ErrorKind::Unsupported => ntstatus::STATUS_NOT_IMPLEMENTED,
        io::ErrorKind::UnexpectedEof => ntstatus::STATUS_END_OF_FILE,
        io::ErrorKind::OutOfMemory => ntstatus::STATUS_NO_MEMORY,
        _ => ntstatus::STATUS_DATA_ERROR,
    }
}

#[derive(Parser)]
struct Arguments {
    #[clap(long, short)]
    /// File to mirror.
    file: String,

    #[clap(long, short)]
    /// Mount point path.
    mount_point: String,

    #[clap(long, short = 't')]
    /// Force a single thread. Otherwise Dokan will allocate the number of
    /// threads regarding the workload
    single_thread: bool,

    #[clap(long, short)]
    /// Enable Dokan's debug output.
    dokan_debug: bool,

    #[clap(long, short)]
    /// Mount as a removable drive.
    removeable: bool,

    #[clap(long, short = 'o')]
    /// Mount using the mount manager
    mount_manager: bool,
}

#[derive(Debug)]
struct FsHandle {
    delta: Mutex<delta::FileDelta<File>>,
}

impl FsHandle {
    pub fn new(file_path: Option<&str>) -> io::Result<Self> {
        let temp = NamedTempFile::new()?;
        Ok(Self {
            delta: Mutex::new(delta::FileDelta::new(
                temp,
                file_path.map(File::open).transpose()?,
            )?),
        })
    }

    pub fn get_delta<'t>(&'t self) -> OperationResult<MutexGuard<'t, delta::FileDelta<File>>> {
        let delta = self
            .delta
            .lock()
            .map_err(|_| ntstatus::STATUS_INTERNAL_ERROR)?;
        Ok(delta)
    }
}

#[derive(Debug)]
enum EntryType {
    Root,
    File,
}

#[derive(Debug)]
enum Entry {
    Root,
    File(Arc<FsHandle>),
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        match self {
            Entry::Root => true,
            Entry::File(_) => false,
        }
    }
    pub fn check_file(&self) -> OperationResult<&FsHandle> {
        match self {
            Entry::Root => Err(ntstatus::STATUS_FILE_IS_A_DIRECTORY),
            Entry::File(file) => Ok(file),
        }
    }
}

trait FileTimesDokanExt {
    fn process_time_op(
        self,
        fop: FileTimeOperation,
        setter: impl Fn(FileTimes, SystemTime) -> FileTimes,
    ) -> Self;
}

impl FileTimesDokanExt for FileTimes {
    fn process_time_op(
        self,
        fop: FileTimeOperation,
        setter: impl Fn(FileTimes, SystemTime) -> FileTimes,
    ) -> Self {
        match fop {
            FileTimeOperation::SetTime(time) => setter(self, time),
            FileTimeOperation::DontChange => self,
            FileTimeOperation::DisableUpdate => self,
            FileTimeOperation::ResumeUpdate => self,
        }
    }
}

struct OverlayFsHandler {
    singleton_name: U16CString,
    file_path: String,
    file_lock: File,
    file_size: u64,
    local_files: Mutex<HashMap<u32, Weak<FsHandle>>>,
}

impl OverlayFsHandler {
    pub fn new(file: &str) -> anyhow::Result<Self> {
        let singleton_name = U16CString::from_str(match file.rsplit_once(&['\\', '/']) {
            Some((_, name)) => name,
            None => file,
        })?;
        let mut file_lock = File::open(file)?;
        file_lock.lock_shared()?;
        let file_size = file_lock.seek(SeekFrom::End(0))?;
        Ok(Self {
            singleton_name,
            file_path: file.into(),
            file_lock,
            file_size,
            local_files: Mutex::default(),
        })
    }
}

impl<'c, 'h: 'c> FileSystemHandler<'c, 'h> for OverlayFsHandler {
    type Context = Entry;

    fn create_file(
        &'h self,
        file_name: &U16CStr,
        _security_context: &IO_SECURITY_CONTEXT,
        _desired_access: winnt::ACCESS_MASK,
        _file_attributes: u32,
        _share_access: u32,
        create_disposition: u32,
        create_options: u32,
        info: &mut OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<CreateFileInfo<Self::Context>> {
        if create_disposition > FILE_MAXIMUM_DISPOSITION {
            return Err(ntstatus::STATUS_INVALID_PARAMETER);
        }

        if (create_options & FILE_DELETE_ON_CLOSE) > 0 {
            return Err(ntstatus::STATUS_CANNOT_DELETE);
        }


        let mut entry = EntryType::Root;
        for part in file_name
            .as_slice()
            .rsplit_once(|c| *c == '$' as u16)
            .unwrap_or((file_name.as_slice(), &[]))
            .0
            .split(|c| *c == '\\' as u16)
            .filter(|c| !c.is_empty())
            .map(|s| U16Str::from_slice(s))
        {
            match entry {
                EntryType::Root => {
                    if part != U16Str::from_slice(self.singleton_name.as_slice()) {
                        return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
                    }
                    entry = EntryType::File;
                }
                EntryType::File => {
                    return Err(ntstatus::STATUS_OBJECT_NAME_NOT_FOUND);
                }
            }
        }

        let entry = match entry {
            EntryType::Root => {
                match create_disposition {
                    FILE_OPEN | FILE_OPEN_IF => Entry::Root,
                    FILE_CREATE => return Err(ntstatus::STATUS_OBJECT_NAME_COLLISION),
                    // FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF
                    _ => return Err(ntstatus::STATUS_INVALID_PARAMETER),
                }
            }
            EntryType::File => {
                if (create_options & FILE_DIRECTORY_FILE) > 0 {
                    return Err(ntstatus::STATUS_NOT_A_DIRECTORY);
                }
                Entry::File(match create_disposition {
                    FILE_CREATE => return Err(ntstatus::STATUS_OBJECT_NAME_COLLISION),
                    FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                        Arc::new(FsHandle::new(None).map_err(to_ntstatus)?)
                    }
                    // FILE_OPEN | FILE_OPEN_IF
                    _ => {
                        let fs = self
                            .local_files
                            .lock()
                            .map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)?
                            .get(&info.pid())
                            .and_then(|fs| fs.upgrade());
                        match fs {
                            Some(fs) => fs,
                            None => {
                                let ret = Arc::new(
                                    FsHandle::new(Some(&self.file_path)).map_err(to_ntstatus)?,
                                );
                                self.local_files
                                    .lock()
                                    .map_err(|_| ntstatus::STATUS_INVALID_PARAMETER)?
                                    .insert(info.pid(), Arc::downgrade(&ret));
                                ret
                            }
                        }
                    }
                })
            }
        };

        Ok(CreateFileInfo {
            is_dir: entry.is_dir(),
            context: entry,
            new_file_created: false,
        })
    }

    fn close_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
    }

    fn read_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        buffer: &mut [u8],
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        let mut delta = context.check_file()?.get_delta()?;
        delta
            .seek(SeekFrom::Start(offset as u64))
            .map_err(to_ntstatus)?;
        delta.read(buffer).map(|sz| sz as u32).map_err(to_ntstatus)
    }

    fn write_file(
        &'h self,
        _file_name: &U16CStr,
        mut offset: i64,
        buffer: &[u8],
        info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<u32> {
        let mut delta = context.check_file()?.get_delta()?;
        if info.write_to_eof() {
            offset = delta.file_size() as i64;
        }
        delta
            .seek(SeekFrom::Start(offset as u64))
            .map_err(to_ntstatus)?;
        delta.write(buffer).map(|sz| sz as u32).map_err(to_ntstatus)
    }

    fn flush_file_buffers(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        let mut delta = context.check_file()?.get_delta()?;
        delta.flush().map_err(to_ntstatus)
    }

    fn get_file_information(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<dokan::FileInfo> {
        let default = SystemTime::UNIX_EPOCH;
        match context {
            Entry::Root => Ok(FileInfo {
                attributes: winnt::FILE_ATTRIBUTE_DIRECTORY,
                creation_time: default,
                last_access_time: default,
                last_write_time: default,
                file_size: 0,
                number_of_links: 1,
                file_index: 0,
            }),
            Entry::File(file) => {
                let delta = file.get_delta()?;
                let meta = delta.metadata().map_err(to_ntstatus)?;
                Ok(FileInfo {
                    attributes: winnt::FILE_ATTRIBUTE_NORMAL,
                    creation_time: meta.created().unwrap_or(default),
                    last_access_time: meta.accessed().unwrap_or(default),
                    last_write_time: meta.modified().unwrap_or(default),
                    file_size: delta.file_size(),
                    number_of_links: 1,
                    file_index: 0,
                })
            }
        }
    }

    fn find_files(
        &'h self,
        _file_name: &U16CStr,
        mut fill_find_data: impl FnMut(&FindData) -> dokan::FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        let default = SystemTime::UNIX_EPOCH;
        match context {
            Entry::Root => {
                let meta = self.file_lock.metadata().map_err(to_ntstatus)?;
                fill_find_data(&FindData {
                    attributes: winnt::FILE_ATTRIBUTE_NORMAL,
                    creation_time: meta.created().unwrap_or(default),
                    last_access_time: meta.accessed().unwrap_or(default),
                    last_write_time: meta.modified().unwrap_or(default),
                    file_size: self.file_size,
                    file_name: self.singleton_name.clone(),
                })
                .or_else(|e| {
                    match e {
                        // Silently ignore this error because file names should
                        // have been small enough when we passed this in
                        FillDataError::NameTooLong => Ok(()),
                        // Normal behavior
                        FillDataError::BufferFull => Err(ntstatus::STATUS_BUFFER_OVERFLOW),
                    }
                })?;
                Ok(())
            }
            Entry::File(_) => Err(ntstatus::STATUS_NOT_A_DIRECTORY),
        }
    }

    fn set_file_attributes(
        &'h self,
        _file_name: &U16CStr,
        _file_attributes: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        match context {
            Entry::Root => (),
            Entry::File(file) => {
                let ft = FileTimes::new().set_accessed(SystemTime::now());
                file.get_delta()?.set_times(ft).map_err(to_ntstatus)?;
            }
        }
        Ok(())
    }

    fn set_file_time(
        &'h self,
        _file_name: &U16CStr,
        creation_time: FileTimeOperation,
        last_access_time: FileTimeOperation,
        last_write_time: FileTimeOperation,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        match context {
            Entry::Root => Ok(()),
            Entry::File(file) => {
                let ft = FileTimes::new()
                    .process_time_op(creation_time, FileTimes::set_created)
                    .process_time_op(last_access_time, FileTimes::set_accessed)
                    .process_time_op(last_write_time, FileTimes::set_modified);

                file.get_delta()?.set_times(ft).map_err(to_ntstatus)
            }
        }
    }

    fn delete_file(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(ntstatus::STATUS_CANNOT_DELETE)
    }

    fn delete_directory(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(ntstatus::STATUS_CANNOT_DELETE)
    }

    fn move_file(
        &'h self,
        _file_name: &U16CStr,
        _new_file_name: &U16CStr,
        _replace_if_existing: bool,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(ntstatus::STATUS_ACCESS_DENIED)
    }

    fn set_end_of_file(
        &'h self,
        _file_name: &U16CStr,
        offset: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        let mut delta = context.check_file()?.get_delta()?;
        let file_size = delta.file_size();
        delta
            .set_end_of_file(file_size + offset as u64)
            .map_err(to_ntstatus)
    }

    fn set_allocation_size(
        &'h self,
        _file_name: &U16CStr,
        alloc_size: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        context: &'c Self::Context,
    ) -> OperationResult<()> {
        // NOTE: this probably is incorrect behavior...
        let mut delta = context.check_file()?.get_delta()?;
        delta
            .set_end_of_file(alloc_size as u64)
            .map_err(to_ntstatus)
    }

    fn get_disk_free_space(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<DiskSpaceInfo> {
        Ok(DiskSpaceInfo {
            byte_count: 1024 * 1024 * 1024,
            free_byte_count: 512 * 1024 * 1024,
            available_byte_count: 512 * 1024 * 1024,
        })
    }

    fn get_volume_information(
        &'h self,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<dokan::VolumeInfo> {
        Ok(VolumeInfo {
            name: U16CString::from_str("overlayfs").unwrap(),
            serial_number: 0,
            max_component_length: MAX_COMPONENT_LENGTH,
            fs_flags: winnt::FILE_CASE_PRESERVED_NAMES
                | winnt::FILE_CASE_SENSITIVE_SEARCH
                | winnt::FILE_UNICODE_ON_DISK
                | winnt::FILE_PERSISTENT_ACLS,
            // Custom names don't play well with UAC.
            fs_name: U16CString::from_str("NTFS").unwrap(),
        })
    }

    fn mounted(
        &'h self,
        _mount_point: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn unmounted(&'h self, _info: &OperationInfo<'c, 'h, Self>) -> OperationResult<()> {
        Ok(())
    }

    fn get_file_security(
        &'h self,
        _file_name: &U16CStr,
        _security_information: u32,
        _security_descriptor: winnt::PSECURITY_DESCRIPTOR,
        _buffer_length: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<u32> {
        Err(ntstatus::STATUS_NOT_IMPLEMENTED)
    }

    fn set_file_security(
        &'h self,
        _file_name: &U16CStr,
        _security_information: u32,
        _security_descriptor: winnt::PSECURITY_DESCRIPTOR,
        _buffer_length: u32,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(ntstatus::STATUS_NOT_IMPLEMENTED)
    }

    fn cleanup(
        &'h self,
        _file_name: &U16CStr,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) {
    }

    fn find_files_with_pattern(
        &'h self,
        _file_name: &U16CStr,
        _pattern: &U16CStr,
        _fill_find_data: impl FnMut(&FindData) -> dokan::FillDataResult,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Err(ntstatus::STATUS_NOT_IMPLEMENTED)
    }

    fn lock_file(
        &'h self,
        _file_name: &U16CStr,
        _offset: i64,
        _length: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Ok(())
    }

    fn unlock_file(
        &'h self,
        _file_name: &U16CStr,
        _offset: i64,
        _length: i64,
        _info: &OperationInfo<'c, 'h, Self>,
        _context: &'c Self::Context,
    ) -> OperationResult<()> {
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let args = Arguments::parse();

    let mount_point = U16CString::from_str(&args.mount_point)?;

    let mut flags = MountFlags::ALT_STREAM;
    if args.mount_manager {
        flags |= MountFlags::MOUNT_MANAGER;
    }
    if args.dokan_debug {
        flags |= MountFlags::DEBUG | MountFlags::STDERR;
    }
    if args.removeable {
        flags |= MountFlags::REMOVABLE;
    }

    let options = MountOptions {
        single_thread: args.single_thread,
        flags,
        ..Default::default()
    };

    let handler = OverlayFsHandler::new(&args.file)?;
    init();

    let mut fsm = FileSystemMounter::new(&handler, &mount_point, &options);

    println!("File system will mount...");
    let fs = fsm.mount()?;
    let mount_point = mount_point.clone();
    ctrlc::set_handler(move || {
        if unmount(&mount_point) {
            println!("File system will unmount...")
        } else {
            eprintln!("Failed to unmount file system.");
        }
    })
    .expect("failed to set Ctrl-C handler");

    println!("File system is mounted, press Ctrl-C to unmount.");
    drop(fs);

    println!("File system is unmounted.");
    shutdown();

    Ok(())
}
