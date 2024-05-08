use clap::Clap;
use core::ffi::c_void;
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;
use abuse::{StorageEngine, Request, Response, CmdFlags, IOVec};

#[derive(Clap)]
struct Opts {
    dev_number: u16
}
#[tokio::main]
async fn main() {
    let opts = Opts::parse();
    let dev_number = opts.dev_number;
    let sz = 1500 << 20; // 1500MB
    let config = abuse::Config {
        dev_number,
        dev_size: sz as u64,
    };
    let engine = Engine {
        mem: Arc::new(RwLock::new(MemBuffer::new(sz))),
    };
    abuse::run_on(config, engine).await;
}

struct Engine {
    mem: Arc<RwLock<MemBuffer>>,
}
#[async_trait]
impl StorageEngine for Engine {
    async fn call(&self, req: Request) -> Response {
        let id = req.request_id;
        let req_op = req.cmd_flags & CmdFlags::OP_MASK;
        match req_op {
            CmdFlags::OP_WRITE => {
                let mut m = self.mem.write().await;
                m.write(req.start as usize, &req.io_vecs);
                Response {
                    request_id: id,
                    errorno: 0,
                }
            },
            CmdFlags::OP_READ => {
                let m = self.mem.read().await;
                m.read(req.start as usize, &req.io_vecs);
                Response {
                    request_id: id,
                    errorno: 0,
                }
            },
            _ => {
                Response {
                    request_id: id,
                    errorno: -libc::EOPNOTSUPP,
                }
            },
        }
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
    fn write(&mut self, offset: usize, io_vecs: &[IOVec]) {
        let mut offset = offset;
        for io_vec in io_vecs {
            let n = io_vec.len();
            let dst = self.buf[offset ..].as_ptr();
            let dst = unsafe { std::mem::transmute::<*const u8, *mut c_void>(dst) };
            unsafe { io_vec.start().copy_to_nonoverlapping(dst, n) };
            offset += n;
        }
    }
    fn read(&self, offset: usize, io_vecs: &[IOVec]) {
        let mut offset = offset;
        for io_vec in io_vecs {
            let n = io_vec.len();
            let src = self.buf[offset ..].as_ptr();
            let src = unsafe { std::mem::transmute::<*const u8, *mut c_void>(src) };
            unsafe { io_vec.start().copy_from_nonoverlapping(src, n) };
            offset += n;
        }
    }
}