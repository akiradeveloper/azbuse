use userland_io::*;
use async_trait::async_trait;
use std::io::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use futures::future::FutureExt;

pub struct Ramdisk {
    buf: Arc<Mutex<Vec<u8>>>,
}
impl Ramdisk {
    pub fn new(n: usize) -> Self {
        Self {
            buf: Arc::new(Mutex::new(vec![0; n]))
        }
    }
}
#[async_trait]
impl StorageEngine for Ramdisk {
    async fn call(&self, req: IORequest) -> Result<IOResponse> {
        match req {
            IORequest::Write { offset, length, fua, payload } => {
                let mut buf = self.buf.lock().await;
                let buf = &mut buf[offset as usize .. offset as usize + length as usize];
                buf.copy_from_slice(&payload);
                Ok(IOResponse::Ok)
            },
            IORequest::Read { offset, length } => {
                let buf = self.buf.lock().await;
                let payload = buf[offset as usize .. offset as usize + length as usize].to_vec();
                Ok(IOResponse::Read {
                    payload,
                })
            },
            IORequest::Flush => {
                Ok(IOResponse::Ok)
            },
            _ => unreachable!(),
        }
    }
}

#[tokio::main]
async fn main() {
    let sz = 16_000_000; // 16MB
    let ramdisk = Ramdisk::new(sz);
    let (backend, tx) = userland_io::IOExecutor::new();
    let export = transport::nbd::Export {
        size: sz as u64,
        readonly: false,
        ..Default::default()
    };
    let frontend = transport::nbd::Server::new(tx, export);
    let socket = "127.0.0.1:10809".parse().unwrap();
    futures::select! {
        () = frontend.serve(socket).fuse() => {},
        () = backend.run(ramdisk).fuse() => {},
    }
}
