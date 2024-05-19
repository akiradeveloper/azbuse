use async_trait::async_trait;
use bitflags::bitflags;
use core::ffi::c_void;
use std::num::NonZeroUsize;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};

bitflags! {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct CmdFlags: u32 {
        const OP_MASK = (1<<8) - 1;
        const OP_UNKNOWN = 0;
        const OP_READ = 1;
        const OP_WRITE = 2;
        const OP_FLUSH = 3;
        const OP_DISCARD = 4;
        const OP_SECURE_ERASE = 5;
        const OP_WRITE_ZEROES = 6;

        const FUA = 1<<8;
        const PREFLUSH = 1<<9;
        const NOUNMAP = 1<<10;
        const NOWAIT = 1<<11;
        const RAHEAD = 1<<12;
    }
}

#[repr(C)]
#[derive(Default, Debug)]
pub struct AzbuseInfo {
    number: u32,
    size: u64,
    blocksize: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct AzbuseXfr {
    id: u64,
    cmd_flags: u32,
    io_offset: u64,
    io_len: u64,
    io_vec_count: u32,
    io_vec_address: u64,
    page_shift: u8,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct AzbuseXfrIoVec {
    pfn: u64,
    n_pages: u32,
    eff_offset: u32,
    eff_len: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct AzbuseCompletion {
    id: u64,
    result: u32,
}

const AZBUSE_GET_STATUS: u16 = 0x4120;
const AZBUSE_SET_STATUS: u16 = 0x4121;
const AZBUSE_RESET: u16 = 0x4122;
const AZBUSE_GET_REQ: u16 = 0x4123;
const AZBUSE_PUT_REQ: u16 = 0x4124;
const AZBUSE_CONNECT: u16 = 0x4188;

nix::ioctl_read_bad!(azbuse_get_status, AZBUSE_GET_STATUS, AzbuseInfo);
nix::ioctl_write_ptr_bad!(azbuse_set_status, AZBUSE_SET_STATUS, AzbuseInfo);
nix::ioctl_none_bad!(azbuse_reset, AZBUSE_RESET);
nix::ioctl_read_bad!(azbuse_get_req, AZBUSE_GET_REQ, AzbuseXfr);
nix::ioctl_write_ptr_bad!(azbuse_put_req, AZBUSE_PUT_REQ, AzbuseCompletion);
nix::ioctl_write_int_bad!(azbuse_connect, AZBUSE_CONNECT);

pub struct IOVec {
    vm_addr: usize,
    vm_len: usize,
    eff_offset: usize,
    eff_len: usize,
}
impl IOVec {
    pub fn start(&self) -> *mut c_void {
        unsafe { std::mem::transmute::<usize, &mut c_void>(self.vm_addr + self.eff_offset) }
    }
    pub fn len(&self) -> usize {
        self.eff_len
    }
}
impl Drop for IOVec {
    fn drop(&mut self) {
        let p = unsafe { std::mem::transmute::<usize, *mut c_void>(self.vm_addr) };
        unsafe { munmap(p, self.vm_len) }.expect("failed to munmap");
    }
}

pub enum IOResult {
    Ok,
    Error(nix::errno::Errno),
}

pub struct Request {
    pub cmd_flags: CmdFlags,
    pub io_start: u64,
    pub io_len: u64,
    pub io_vecs: Vec<IOVec>,
    pub request_id: u64,
    fd: i32,
    completed: bool,
}
impl Request {
    pub fn endio(mut self, result: IOResult) {
        let errno = match result {
            IOResult::Ok => 0,
            IOResult::Error(e) => e as i32,
        };
        let cmplt = AzbuseCompletion {
            id: self.request_id,
            result: errno as u32,
        };
        unsafe { azbuse_put_req(self.fd, &cmplt) }.expect("failed to put req");
        self.completed = true;
    }
}
impl Drop for Request {
    fn drop(&mut self) {
        if !self.completed {
            self.endio(IOResult::Error(nix::errno::Errno::EIO));
        }
    }
}

#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn call(&mut self, req: Request);
}

struct RequestHandler<Engine: StorageEngine> {
    rx: tokio::sync::mpsc::UnboundedReceiver<Request>,
    engine: Engine,
}
impl <Engine: StorageEngine> RequestHandler<Engine> {
    async fn run(mut self) {
        while let Some(req) = self.rx.recv().await {
            self.engine.call(req).await;
        }
    }
}

const BIO_MAX_VECS: usize = 256;

pub struct Config {
    pub minor: u16,
    pub device_size: u64,
}

pub async fn run_on(config: Config, engine: impl StorageEngine) {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;

    let fd = open("/dev/azbusectl", OFlag::O_RDWR, Mode::empty()).expect("couldn't open /dev/azbusectl");
    let devfd = {
        let devpath = format!("/dev/azbuse{}", config.minor);
        open(devpath.as_str(), OFlag::empty(), Mode::empty()).expect("couldn't open device")
    };

    // This attaches struct azb_device to ctlfd->private_data
    unsafe { azbuse_connect(fd, devfd) }.expect("couldn't acquire azbuse device");
    let mut info = AzbuseInfo::default();
    unsafe { azbuse_get_status(fd, &mut info) }.expect("couldn't get info");
    dbg!(&info);
    unsafe { azbuse_reset(fd) }.expect("couldn't reset device");
    // size must be some multiple of blocksize
    info.size = config.device_size;
    info.blocksize = 4096;
    unsafe { azbuse_set_status(fd, &info) }.expect("couldn't set info");

    let mut poll = Poll::new().unwrap();
    let mut source = SourceFd(&fd);
    poll.registry()
        .register(&mut source, Token(0), Interest::READABLE)
        .expect("failed to set up poll");
    let mut events = Events::with_capacity(1);

    let iovec = [AzbuseXfrIoVec::default(); BIO_MAX_VECS];
    let io_vec_address: u64 =
        unsafe { std::mem::transmute::<*const AzbuseXfrIoVec, u64>(iovec.as_ptr()) };
    let mut xfr = AzbuseXfr {
        io_vec_address,
        ..AzbuseXfr::default()
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let request_handler = RequestHandler {
        rx,
        engine,
    };
    tokio::spawn(request_handler.run());
    
    loop {
        // When there are some requests in the in-kernel queue, this returns events including Token(0).
        // Then the internal loop consumes all requests in the queue.
        poll.poll(&mut events, None).expect("failed to poll");
        'poll: for ev in &events {
            loop {
                if let Err(e) = unsafe { azbuse_get_req(fd, &mut xfr) } {
                    break 'poll;
                }

                let n = xfr.io_vec_count as usize;
                let xfr_io_vec = {
                    let out = unsafe {
                        std::mem::transmute::<u64, *const AzbuseXfrIoVec>(xfr.io_vec_address)
                    };
                    let out = unsafe { std::slice::from_raw_parts(out, n) };
                    out
                };

                let prot_flags = {
                    let mut out = ProtFlags::empty();
                    out.insert(ProtFlags::PROT_READ);
                    out.insert(ProtFlags::PROT_WRITE);
                    out
                };

                let map_flags = {
                    let mut out = MapFlags::empty();
                    out.insert(MapFlags::MAP_SHARED);
                    out.insert(MapFlags::MAP_POPULATE);
                    out.insert(MapFlags::MAP_NONBLOCK);
                    out
                };

                let mut tot_n_pages = 0;
                for i in 0..n {
                    tot_n_pages += xfr_io_vec[i].n_pages;
                }
                // mmap all pages in the bvecs at once.
                let vm_len = tot_n_pages << xfr.page_shift;
                let p = unsafe { mmap(None, NonZeroUsize::new(vm_len as usize).unwrap(), prot_flags, map_flags, fd, 0) }.expect("failed to mmap");

                let mut cur = unsafe { std::mem::transmute::<*const c_void, usize>(p) };
                let mut io_vecs = vec![];
                for i in 0..n {
                    let io_vec = &xfr_io_vec[i];
                    let map_len = (io_vec.n_pages << xfr.page_shift) as usize;
                    io_vecs.push(IOVec {
                        vm_addr: cur,
                        vm_len: map_len,
                        eff_offset: io_vec.eff_offset as usize,
                        eff_len: io_vec.eff_len as usize,
                    });
                    cur += map_len;
                }
                
                let cmd_flags = CmdFlags::from_bits(xfr.cmd_flags).unwrap();
                let req = Request {
                    cmd_flags,
                    io_vecs,
                    io_start: xfr.io_offset,
                    io_len: xfr.io_len,
                    request_id: xfr.id,
                    fd,
                    completed: false,
                };

                tx.send(req).unwrap();
            }
        }
    }
}