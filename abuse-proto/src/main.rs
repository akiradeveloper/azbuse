use clap::Clap;
use mio::{Poll, Interest, Token, Events};
use mio::unix::SourceFd;
use core::ffi::c_void;
use nix::sys::mman::{mmap, munmap, ProtFlags, MapFlags};

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
    command: u32,
    io_vec_count: u32,
    io_vec_address: u64,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct AbuseXfrIoVec {
    address: u64,
    offset: u32,
    len: u32,
}
#[repr(C)]
#[derive(Default)]
pub struct AbuseCompletion {
    id: u64,
    result: u32,
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

struct IoChunk {
    page_address: usize,
    page_offset: usize,
    io_len: usize,
}
impl IoChunk {
    fn start(&self) -> *mut c_void {
        unsafe { std::mem::transmute::<usize, &mut c_void>(self.page_address + self.page_offset) }
    }
    fn len(&self) -> usize {
        self.io_len
    }
}
impl Drop for IoChunk {
    fn drop(&mut self) {
        let p = unsafe { std::mem::transmute::<usize, *mut c_void>(self.page_address) };
        let map_len = self.page_offset + self.io_len;
        unsafe { munmap(p, map_len) }.expect("failed to munmap");
    }
}

struct MemBuffer {
    buf: Vec<u8>,
}
impl MemBuffer {
    fn new(n: usize) -> Self {
        Self {
            buf: vec![0;n],
        }
    }
    fn write(&mut self, offset: usize, io_chunks: &[IoChunk]) {
        let mut offset = offset;
        for io_chunk in io_chunks {
            let n = io_chunk.len();
            let mut dst = self.buf[offset ..].as_ptr();
            let dst = unsafe { std::mem::transmute::<*const u8, *mut c_void>(dst) };
            unsafe { io_chunk.start().copy_to_nonoverlapping(dst, n) };
            offset += n;
        }
    }
    fn read(&self, offset: usize, io_chunks: &[IoChunk]) {
        let mut offset = offset;
        for io_chunk in io_chunks {
            let n = io_chunk.len();
            let src = self.buf[offset ..].as_ptr();
            let src = unsafe { std::mem::transmute::<*const u8, *mut c_void>(src) };
            unsafe { io_chunk.start().copy_from_nonoverlapping(src, n) };
            offset += n;
        }
    }
}

// This could be BIO_MAX_VECS = 256 (in 5.10)
const MAX_QUEUE: usize = 1<<16;

#[derive(Clap)]
struct Opts {
    dev_number: u16
}
fn main() {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;

    let opts = Opts::parse();
    let fd = open("/dev/abctl", OFlag::O_RDWR, Mode::empty()).expect("couldn't open /dev/abctl");
    let devpath = format!("/dev/abuse{}", opts.dev_number);
    let devfd = open(devpath.as_str(), OFlag::empty(), Mode::empty()).expect("couldn't open device");

    let sz = 4096 * 40_000; // 160MB
    let mut membuf = MemBuffer::new(sz as usize);

    // This attaches struct ab_device to ctlfd->private_data 
    unsafe { abuse_acquire(fd, devfd) }.expect("couldn't acquire abuse device");
    let mut info = AbuseInfo::default();
    unsafe { abuse_get_status(fd, &mut info) }.expect("couldn't get info");
    dbg!(&info);
    unsafe { abuse_reset(fd) }.expect("couldn't reset device");
    // size must be some multiple of blocksize
    info.size = sz;
    info.blocksize = 4096;
    info.max_queue = MAX_QUEUE as u32;
    if let Err(e) = unsafe { abuse_set_status(fd, &info) } {
        println!("couldn't set info. ({})", e);
    }

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

    println!("start polling ...");
    loop {
        // timeout = None
        poll.poll(&mut events, None).expect("failed to poll");
        'poll: for ev in &events {
            println!("got events!");
            loop {
                if let Err(e) = unsafe { abuse_get_req(fd, &mut xfr) } {
                    break 'poll;
                }

                let n = xfr.io_vec_count as usize;
                let xfr_io_vec = unsafe { std::mem::transmute::<u64, *const AbuseXfrIoVec>(xfr.io_vec_address) };
                let xfr_io_vec = unsafe { std::slice::from_raw_parts(xfr_io_vec, n) };
                println!("id={},command={},offset={},io_vec_cnt={}", xfr.id, xfr.command, xfr.offset, xfr.io_vec_count);

                let mut chunks = vec![];
                for i in 0..n {
                    let io_vec = &xfr_io_vec[i];
                    println!("addr={:0x},offset={},len={}", io_vec.address, io_vec.offset, io_vec.len);
                    assert!(io_vec.address % 4096 == 0);

                    // experimental: let's see overhead!
                    let p0 = unsafe { std::mem::transmute::<usize, *mut c_void>(0) };
                    let page_address = io_vec.address as i64;
                    println!("page_address={}", page_address);
                    let map_len = io_vec.offset as usize + io_vec.len as usize;
                    let mut prot_flags = ProtFlags::empty();
                    prot_flags.insert(ProtFlags::PROT_READ);
                    prot_flags.insert(ProtFlags::PROT_WRITE);
                    let mut map_flags = MapFlags::empty();
                    map_flags.insert(MapFlags::MAP_SHARED);
                    map_flags.insert(MapFlags::MAP_POPULATE);
                    let p = unsafe { mmap(p0, map_len, prot_flags, map_flags, fd, page_address) }.expect("failed to mmap");
                    println!("p(mapped)={:?}", p);

                    chunks.push(IoChunk {
                        page_address: unsafe { std::mem::transmute::<*const c_void, usize>(p) },
                        page_offset: io_vec.offset as usize,
                        io_len: io_vec.len as usize,
                    });
                }

                if xfr.command == 0 {
                    membuf.read(xfr.offset as usize, &chunks);
                } else {
                    membuf.write(xfr.offset as usize, &chunks);
                }

                let cmplt = AbuseCompletion {
                    id: xfr.id,
                    result: 0, // ok. tmp
                };
                unsafe { abuse_put_req(fd, &cmplt) }.expect("failed to put req");
            }
        }
    }
}