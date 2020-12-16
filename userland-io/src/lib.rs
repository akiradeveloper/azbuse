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
                    IORequest::Echo(n) => {
                        let resp = Response { inner: Ok(IOResponse::Echo(n)), context };
                        let _ = tx.send(resp);
                    },
                    req => {
                        let resp_inner = engine.call(req).await;
                        let resp = Response { inner: resp_inner, context };
                        let _ = tx.send(resp);
                    }
                }
            };
            tokio::spawn(fut);
        }
    }
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
    Echo(u32),
}
pub enum IOResponse {
    Ok,
    Read { 
        payload: Vec<u8>,
    },
    Echo(u32),
}
pub struct Request {
    inner: IORequest,
    tx: UnboundedSender<Response>,
    context: Vec<u8>,
}
struct Response {
    inner: Result<IOResponse>,
    context: Vec<u8>,
}

#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn call(&self, req: IORequest) -> Result<IOResponse>;
}