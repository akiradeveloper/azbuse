#![deny(unused_must_use)]

use std::io::Result;
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use async_trait::async_trait;
use std::sync::Arc;

pub mod transport;

pub enum IORequest {
    Write {
        offset: u64,
        length: u32,
        payload: Vec<u8>,
        fua: bool,
    },
    Read {
        offset: u64,
        length: u32,
    },
    Flush,
    // below not used yet.
    // Trim {
    //     offset: u64,
    //     length: u32,
    // },
    // WriteZeros {
    //     offset: u64,
    //     length: u32,
    //     fua: bool,
    // },
    Unknown,
}
pub enum IOResponse {
    Ok,
    Read { 
        payload: Vec<u8>,
    },
}
struct Response {
    inner: Result<IOResponse>,
    request_id: u64,
}

#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn call(&self, req: IORequest) -> Result<IOResponse>;
}