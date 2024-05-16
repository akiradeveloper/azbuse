use abuse::{CmdFlags, IOVec, Request, Response, StorageEngine};
use async_trait::async_trait;
use clap::Parser;
use core::ffi::c_void;

#[derive(Parser)]
struct Opts {
    dev_number: u16,
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
        mem: MemBuffer::new(sz),
    };
    abuse::run_on(config, engine).await;
}

struct Engine {
    mem: MemBuffer,
}
#[async_trait]
impl StorageEngine for Engine {
    async fn call(&mut self, req: Request) -> Response {
        let id = req.request_id;
        let req_op = req.cmd_flags & CmdFlags::OP_MASK;
        match req_op {
            CmdFlags::OP_WRITE => {
                let m = &mut self.mem;
                m.write(req.start as usize, &req.io_vecs);
                Response {
                    request_id: id,
                    errorno: 0,
                }
            }
            CmdFlags::OP_READ => {
                let m = &self.mem;
                m.read(req.start as usize, &req.io_vecs);
                Response {
                    request_id: id,
                    errorno: 0,
                }
            }
            _ => Response {
                request_id: id,
                errorno: -libc::EOPNOTSUPP,
            },
        }
    }
}
struct MemBuffer {
    buf: Vec<u8>,
}
impl MemBuffer {
    fn new(n: usize) -> Self {
        Self { buf: vec![0; n] }
    }
    fn write(&mut self, offset: usize, io_vecs: &[IOVec]) {
        let mut cur = offset;

        for io_vec in io_vecs {
            let dst = self.buf[cur..].as_ptr();
            let dst = unsafe { std::mem::transmute::<*const u8, *mut c_void>(dst) };

            let len = io_vec.len();
            unsafe { io_vec.start().copy_to_nonoverlapping(dst, len) };
            cur += len;
        }
    }
    fn read(&self, offset: usize, io_vecs: &[IOVec]) {
        let mut cur = offset;

        for io_vec in io_vecs {
            let src = self.buf[cur..].as_ptr();
            let src = unsafe { std::mem::transmute::<*const u8, *mut c_void>(src) };

            let len = io_vec.len();
            unsafe { io_vec.start().copy_from_nonoverlapping(src, len) };
            cur += len;
        }
    }
}
