use fs2::FileExt;
use lru::LruCache;
use std::{
    fs::{FileTimes, Metadata},
    io::{self, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
};
use tempfile::NamedTempFile;

const PAGE_DIR_LEVELS: usize = 3;
const PAGE_DIR_SHIFT: usize = 10;
const PAGE_DIR_SIZE: usize = 1 << PAGE_DIR_SHIFT;
const PAGE_SHIFT: usize = 12;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT;
const INVALID_PAGE: u32 = 0;
const PAGE_INIT: [u8; PAGE_SIZE] = [0x0; PAGE_SIZE];
const CACHE_SIZE: NonZeroUsize = NonZeroUsize::new(100).unwrap();

type PageData = Box<[u32; PAGE_DIR_SIZE]>;

#[derive(Debug)]
pub struct FileDelta<F> {
    pub(crate) delta: NamedTempFile,
    next_page: u32,
    underneath: Option<F>,
    offset: u64,
    delta_size: u64,
    file_size: u64,
    original_file_size: u64,
    page_cache: LruCache<u32, PageData>,
}

fn split_levels(mut offset: u64) -> io::Result<(usize, [usize; PAGE_DIR_LEVELS])> {
    let poff = offset as usize & (PAGE_SIZE - 1);
    let mut page_inds = [0; PAGE_DIR_LEVELS];
    offset >>= PAGE_SHIFT;
    for i in 0..PAGE_DIR_LEVELS {
        page_inds[PAGE_DIR_LEVELS - i - 1] = (offset & ((1 << PAGE_DIR_SHIFT) - 1)) as usize;
        offset >>= PAGE_DIR_SHIFT;
    }

    if offset != 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }

    Ok((poff, page_inds))
}

#[derive(Debug)]
enum Page {
    Backed(u32),
    Underlying(u64),
}

impl<F: Seek + Read> FileDelta<F> {
    pub fn new(mut delta: NamedTempFile, mut underneath: Option<F>) -> io::Result<Self> {
        delta.as_file().lock_exclusive()?;
        let mut delta_size = delta.seek(SeekFrom::End(0))?;
        if delta_size == 0 {
            delta.write_all(&PAGE_INIT)?;
            delta_size += PAGE_SIZE as u64;
        }

        let file_size = underneath
            .as_mut()
            .map(|f| f.seek(SeekFrom::End(0)))
            .transpose()?
            .unwrap_or_default();
        let ret = Self {
            delta,
            underneath,
            offset: 0,
            delta_size,
            file_size,
            original_file_size: file_size,
            next_page: (delta_size / PAGE_SIZE as u64)
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidInput)?,
            page_cache: LruCache::new(CACHE_SIZE),
        };

        Ok(ret)
    }

    fn get_page_and_offset(&mut self, offset: u64) -> io::Result<(usize, Page)> {
        let (poff, page_inds) = split_levels(offset)?;
        let mut cur_num = 0;
        for page_ind in page_inds {
            let page = self.read_page(Page::Backed(cur_num))?;
            cur_num = page[page_ind];
            if cur_num == INVALID_PAGE {
                return Ok((poff, Page::Underlying(offset)));
            }
        }

        Ok((poff, Page::Backed(cur_num)))
    }

    fn copy_page_and_offset(&mut self, offset: u64) -> io::Result<(usize, u32, PageData)> {
        let (poff, page_inds) = split_levels(offset)?;
        let mut cur_num = 0;
        let mut created = false;
        for page_ind in page_inds {
            created = false;
            let mut page = self.read_page(Page::Backed(cur_num))?;
            let mut new_num = page[page_ind];
            if new_num == INVALID_PAGE {
                new_num = self.create_page()?;
                page[page_ind] = new_num;
                self.write_page(cur_num, &page)?;
                created = true;
            }
            cur_num = new_num;
        }

        let page = if created {
            let page = self.read_page(Page::Underlying(offset))?;
            self.write_page(cur_num, &page)?;
            page
        } else {
            self.read_page(Page::Backed(cur_num))?
        };
        Ok((poff, cur_num, page))
    }

    fn create_page(&mut self) -> io::Result<u32> {
        let num = self.next_page;
        self.next_page += 1;
        self.delta_size += PAGE_SIZE as u64;
        self.delta.seek(SeekFrom::Start(
            (num as usize * PAGE_SIZE)
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        ))?;
        self.delta.write_all(&PAGE_INIT)?;
        Ok(num)
    }

    fn write_page(&mut self, num: u32, page: &PageData) -> io::Result<()> {
        if num >= self.next_page {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.delta.seek(SeekFrom::Start(
            (num as usize * PAGE_SIZE)
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        ))?;
        self.delta.write_all(bytemuck::bytes_of(&**page))?;

        if self.page_cache.contains(&num) {
            self.page_cache.put(num, page.clone());
        }
        Ok(())
    }

    fn read_page(&mut self, num: Page) -> io::Result<PageData> {
        let mut page = Box::new([0; PAGE_DIR_SIZE]);
        match num {
            Page::Backed(num) => {
                if num >= self.next_page {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let found_page = self.page_cache.try_get_or_insert(num, || {
                    let mut page = Box::new([0; PAGE_DIR_SIZE]);
                    self.delta.seek(SeekFrom::Start(
                        (num as usize * PAGE_SIZE)
                            .try_into()
                            .map_err(|_| io::ErrorKind::InvalidData)?,
                    ))?;
                    self.delta.read_exact(bytemuck::bytes_of_mut(&mut *page))?;
                    io::Result::Ok(page)
                })?;
                page.copy_from_slice(&**found_page);
            }
            Page::Underlying(offset) => {
                let page_offset = offset & !(PAGE_SIZE as u64 - 1);
                if let Some(underneath) = &mut self.underneath {
                    if self.original_file_size > page_offset {
                        let rem_size =
                            ((self.original_file_size - page_offset) as usize).min(PAGE_SIZE);
                        underneath.seek(SeekFrom::Start(page_offset))?;
                        underneath
                            .read_exact(&mut bytemuck::bytes_of_mut(&mut *page)[..rem_size])?;
                    }
                }
            }
        }
        Ok(page)
    }

    pub fn metadata(&self) -> io::Result<Metadata> {
        self.delta.as_file().metadata()
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    pub fn set_times(&self, times: FileTimes) -> io::Result<()> {
        self.delta.as_file().set_times(times)
    }

    pub fn set_end_of_file(&mut self, offset: u64) -> io::Result<()> {
        self.file_size = self.file_size.max(offset);
        if offset > self.file_size {
            self.copy_page_and_offset(offset)?;
        }
        Ok(())
    }
}

impl<F: Seek> Seek for FileDelta<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.offset = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => self.delta_size.strict_add_signed(offset),
            SeekFrom::Current(offset) => self.offset.strict_add_signed(offset),
        };

        Ok(self.offset)
    }
}

impl<F: Seek + Read> Read for FileDelta<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut readsz = 0;
        while readsz < buf.len() {
            let (poff, page) = self.get_page_and_offset(self.offset)?;
            let page = self.read_page(page)?;
            let data = &bytemuck::bytes_of(&*page)[poff..];
            let chunk_sz = data.len().min(buf.len() - readsz);

            buf[readsz..readsz + chunk_sz].copy_from_slice(&data[..chunk_sz]);

            readsz += chunk_sz;
            self.offset += chunk_sz as u64;
        }
        Ok(readsz)
    }
}

impl<F: Seek + Read> Write for FileDelta<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file_size = self.file_size.max(self.offset + buf.len() as u64);
        let mut writesz = 0;
        while writesz < buf.len() {
            let (poff, num, mut page) = self.copy_page_and_offset(self.offset)?;
            let data = &mut bytemuck::bytes_of_mut(&mut *page)[poff..];
            let chunk_sz = data.len().min(buf.len() - writesz);

            data[..chunk_sz].copy_from_slice(&buf[writesz..writesz + chunk_sz]);
            self.write_page(num, &page)?;

            writesz += chunk_sz;
            self.offset += chunk_sz as u64;
        }
        Ok(writesz)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.delta.flush()
    }
}
