#![deny(unused_must_use)]

use std::io::Result;
use tokio::sync::mpsc::{self, Sender, Receiver};
use async_trait::async_trait;
use std::sync::Arc;

pub mod transport;

pub struct IOExecutor {
    rx: Receiver<Request>,
}
impl IOExecutor {
    pub fn new() -> (Self, Sender<Request>) {
        let (request_tx, request_rx) = mpsc::channel(64);
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
                        let _ = tx.send(resp).await;
                    },
                    req => {
                        let resp_inner = engine.call(req).await;
                        let resp = Response { inner: resp_inner, context };
                        let _ = tx.send(resp).await;
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
    pub inner: IORequest,
    pub tx: Sender<Response>,
    pub context: Vec<u8>,
}
pub struct Response {
    pub inner: Result<IOResponse>,
    pub context: Vec<u8>,
}

#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn call(&self, req: IORequest) -> Result<IOResponse>;
}