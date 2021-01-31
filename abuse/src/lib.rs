use async_trait::async_trait;
use bitflags::bitflags;
use nix::sys::mman::{mmap, munmap, ProtFlags, MapFlags};
use core::ffi::c_void;
use mio::{Poll, Interest, Token, Events};
use mio::unix::SourceFd;
use std::sync::Arc;

bitflags! {
    pub struct CmdFlags: u32 {
        const OP_MASK = (1<<8) - 1;
        const OP_UNKNOWN = 0;
        const OP_WRITE = 1;
        const OP_READ = 2;
        const OP_FLUSH = 3;
        const OP_WRITE_SAME = 4;
        const OP_WRITE_ZEROES = 5;
        const OP_DISCARD = 6;
        const OP_SECURE_ERASE = 7;

        const FUA = 1<<8;
        const PREFLUSH = 1<<9;
        const NOUNMAP = 1<<10;
        const NOWAIT = 1<<11;
        const RAHEAD = 1<<12;
    }
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct AbuseInfo {
    device: u64,
    size: u64,
    number: u32,
    flags: u32,
    blocksize: u32,
    max_queue: u32,
    queue_size: u32,
    errors: u32,
    max_vecs: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct AbuseXfr {
    id: u64,
    offset: u64,
    len: u64,
    cmd_flags: u32,
    io_vec_count: u32,
    io_vec_address: u64,
    n_pages: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct AbuseXfrIoVec {
    address: u64,
    offset: u32,
    len: u32,
    n_pages: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct AbuseCompletion {
    id: u64,
    result: i32,
}

const ABUSE_GET_STATUS: u16 = 0x4120;
const ABUSE_SET_STATUS: u16 = 0x4121;
const ABUSE_SET_POLL: u16 = 0x4122;
const ABUSE_RESET: u16 = 0x4123;
const ABUSE_GET_REQ: u16 = 0x4124;
const ABUSE_PUT_REQ: u16 = 0x4125;

const ABUSE_CTL_ADD: u16 = 0x4186;
const ABUSE_CTL_REMOVE: u16 = 0x4187;
const ABUSE_CTL_GET_FREE: u16 = 0x4188;

const ABUSE_ACQUIRE: u16 = 0x4189;
const ABUSE_RELEASE: u16 = 0x418A;

nix::ioctl_none_bad!(abuse_reset, ABUSE_RESET);
nix::ioctl_none_bad!(abuse_release, ABUSE_RELEASE);
nix::ioctl_write_ptr_bad!(abuse_set_status, ABUSE_SET_STATUS, AbuseInfo);
nix::ioctl_write_int_bad!(abuse_acquire, ABUSE_ACQUIRE);
nix::ioctl_read_bad!(abuse_get_status, ABUSE_GET_STATUS, AbuseInfo);
nix::ioctl_read_bad!(abuse_get_req, ABUSE_GET_REQ, AbuseXfr);
nix::ioctl_write_ptr_bad!(abuse_put_req, ABUSE_PUT_REQ, AbuseCompletion);

pub struct IOVec {
    page_address: usize,
    page_offset: usize,
    io_len: usize,
}
impl IOVec {
    pub fn start(&self) -> *mut c_void {
        unsafe { std::mem::transmute::<usize, &mut c_void>(self.page_address + self.page_offset) }
    }
    pub fn len(&self) -> usize {
        self.io_len
    }
}
impl Drop for IOVec {
    fn drop(&mut self) {
        let p = unsafe { std::mem::transmute::<usize, *mut c_void>(self.page_address) };
        let map_len = self.page_offset + self.io_len;
        unsafe { munmap(p, map_len) }.expect("failed to munmap");
    }
}

pub struct Request {
    pub cmd_flags: CmdFlags,
    pub start: u64,
    pub len: u64,
    pub io_vecs: Vec<IOVec>,
    pub request_id: u64,
}

pub struct Response {
    pub errorno: i32,
    pub request_id: u64,
}

#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn call(&self, req: Request) -> Response;
}

// This could be BIO_MAX_VECS = 256 (in 5.10)
const MAX_QUEUE: usize = 1<<16;

pub struct Config {
    pub dev_number: u16,
    pub dev_size: u64,
}

pub async fn run_on(config: Config, engine: impl StorageEngine) {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;

    let engine = Arc::new(engine);
    let fd = open("/dev/abctl", OFlag::O_RDWR, Mode::empty()).expect("couldn't open /dev/abctl");
    let devpath = format!("/dev/abuse{}", config.dev_number);
    let devfd = open(devpath.as_str(), OFlag::empty(), Mode::empty()).expect("couldn't open device");

    // This attaches struct ab_device to ctlfd->private_data 
    unsafe { abuse_acquire(fd, devfd) }.expect("couldn't acquire abuse device");
    let mut info = AbuseInfo::default();
    unsafe { abuse_get_status(fd, &mut info) }.expect("couldn't get info");
    dbg!(&info);
    unsafe { abuse_reset(fd) }.expect("couldn't reset device");
    // size must be some multiple of blocksize
    info.size = config.dev_size;
    info.blocksize = 4096;
    info.max_queue = MAX_QUEUE as u32;
    unsafe { abuse_set_status(fd, &info) }.expect("couldn't set info");

    let mut poll = Poll::new().unwrap();
    let mut source = SourceFd(&fd);
    poll.registry().register(
        &mut source,
        Token(0),
        Interest::READABLE,
    ).expect("failed to set up poll");
    let mut events = Events::with_capacity(1);

    let iovec = [AbuseXfrIoVec::default(); MAX_QUEUE];
    let io_vec_address: u64 = unsafe {
            std::mem::transmute::<* const AbuseXfrIoVec, u64>(iovec.as_ptr())
    };
    let mut xfr = AbuseXfr {
        io_vec_address,
        .. AbuseXfr::default()
    };
    loop {
        // timeout = None
        poll.poll(&mut events, None).expect("failed to poll");
        'poll: for ev in &events {
            loop {
                if let Err(e) = unsafe { abuse_get_req(fd, &mut xfr) } {
                    break 'poll;
                }

                let n = xfr.io_vec_count as usize;
                let xfr_io_vec = unsafe { std::mem::transmute::<u64, *const AbuseXfrIoVec>(xfr.io_vec_address) };
                let xfr_io_vec = unsafe { std::slice::from_raw_parts(xfr_io_vec, n) };

                let mut io_vecs = vec![];
                for i in 0..n {
                    let io_vec = &xfr_io_vec[i];
                    assert!(io_vec.address % 4096 == 0);

                    let p0 = unsafe { std::mem::transmute::<usize, *mut c_void>(0) };
                    let page_address = io_vec.address as i64;
                    let map_len = io_vec.offset as usize + io_vec.len as usize;
                    println!("pfn={}, len={} bytes", page_address >> 9, map_len);
                    let mut prot_flags = ProtFlags::empty();
                    prot_flags.insert(ProtFlags::PROT_READ);
                    prot_flags.insert(ProtFlags::PROT_WRITE);
                    let mut map_flags = MapFlags::empty();
                    map_flags.insert(MapFlags::MAP_SHARED);
                    map_flags.insert(MapFlags::MAP_POPULATE);
                    map_flags.insert(MapFlags::MAP_NONBLOCK);
                    // Last argument page_offset should be a multiple of page size
                    // This passes to xxx_mmap as vma.pg_off after 9 right shift.
                    let p = unsafe { mmap(p0, map_len, prot_flags, map_flags, fd, page_address) }.expect("failed to mmap");

                    io_vecs.push(IOVec {
                        page_address: unsafe { std::mem::transmute::<*const c_void, usize>(p) },
                        page_offset: io_vec.offset as usize,
                        io_len: io_vec.len as usize,
                    });
                }
                let cmd_flags = CmdFlags::from_bits(xfr.cmd_flags).unwrap();
                let req = Request {
                    cmd_flags,
                    io_vecs,
                    start: xfr.offset,
                    len: xfr.len,
                    request_id: xfr.id,
                };
                let engine = Arc::clone(&engine);
                // tmp (BUG)
                // tokio::spawn(async move {
                    let req_id = req.request_id;
                    let res = engine.call(req).await;
                    let cmplt = AbuseCompletion {
                        id: req_id,
                        result: res.errorno,
                    };
                    unsafe { abuse_put_req(fd, &cmplt) }.expect("failed to put req");
                // });
            } 
        }
    }
}