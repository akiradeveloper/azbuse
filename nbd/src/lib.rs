#![deny(unused_must_use)]

use std::io::Result;
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use async_trait::async_trait;
use std::sync::Arc;

pub mod transport;

pub struct IOExecutor {
    rx: UnboundedReceiver<Request>,
}
impl IOExecutor {
    pub fn new() -> (Self, UnboundedSender<Request>) {
        let (request_tx, request_rx) = mpsc::unbounded_channel();
        let x = Self {
            rx: request_rx,
        };
        (x, request_tx)
    }
    pub async fn run<E: StorageEngine>(mut self, engine: E) {
        let engine = Arc::new(engine);
        while let Some(req) = self.rx.recv().await {
            let engine = Arc::clone(&engine);
            let fut = async move {
                let Request { inner, tx, context } = req;
                match inner {
                    IORequestInner::Echo(n) => {
                        let resp = Response { inner: Ok(IOResponseInner::Echo(n)), context };
                        let _ = tx.send(resp);
                    },
                    IORequestInner::IORequest(req) => {
                        let resp_inner = engine.call(req).await;
                        let resp = Response { inner: resp_inner.map(|x| IOResponseInner::IOResponse(x)), context };
                        let _ = tx.send(resp);
                    }
                }
            };
            tokio::spawn(fut);
        }
    }
}
enum IORequestInner {
    IORequest(IORequest),
    Echo(u32),
}
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
}
enum IOResponseInner {
    IOResponse(IOResponse),
    Echo(u32),
}
pub enum IOResponse {
    Ok,
    Read { 
        payload: Vec<u8>,
    },
}
pub struct Request {
    inner: IORequestInner,
    tx: UnboundedSender<Response>,
    context: Vec<u8>,
}
struct Response {
    inner: Result<IOResponseInner>,
    context: Vec<u8>,
}

#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn call(&self, req: IORequest) -> Result<IOResponse>;
}