use nbd::*;
use async_trait::async_trait;
use std::io::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use futures::future::FutureExt;

pub struct Ramdisk {
    buf: Arc<RwLock<Vec<u8>>>,
}
impl Ramdisk {
    pub fn new(n: usize) -> Self {
        Self {
            buf: Arc::new(RwLock::new(vec![0; n]))
        }
    }
}
#[async_trait]
impl StorageEngine for Ramdisk {
    async fn call(&self, req: IORequest) -> Result<IOResponse> {
        match req {
            IORequest::Write { offset, length, fua, payload } => {
                let mut buf = self.buf.write().await;
                let buf = &mut buf[offset as usize .. offset as usize + length as usize];
                buf.copy_from_slice(&payload);
                Ok(IOResponse::Ok)
            },
            IORequest::Read { offset, length } => {
                let buf = self.buf.read().await;
                let payload = buf[offset as usize .. offset as usize + length as usize].to_vec();
                Ok(IOResponse::Read {
                    payload,
                })
            },
            IORequest::Flush => {
                Ok(IOResponse::Ok)
            },
            IORequest::Unknown => {
                Err(std::io::Error::from_raw_os_error(95))
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let sz = 1500 << 20; // 1500MB
    let engine = Ramdisk::new(sz);
    let export = transport::Export {
        size: sz as u64,
        readonly: false,
        ..Default::default()
    };
    let server = transport::Server::new(export);
    let socket = "127.0.0.1:10809".parse().unwrap();
    server.serve(socket, engine).await;
}