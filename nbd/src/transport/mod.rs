use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpListener};
use tokio_stream::StreamExt;
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use tokio::io::{ReadHalf, WriteHalf, AsyncWriteExt, AsyncReadExt};
use crate::{Response, IORequest, IOResponse, StorageEngine};
use std::io::Result;
use protocol::io;
use futures::select;
use futures::future::FutureExt;
use std::sync::Arc;

mod protocol;
use protocol::handshake::*;
use protocol::consts::*;
use protocol::transmission::reply;

pub use protocol::handshake::Export;

fn strerror(s: &'static str) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, s))
}

struct RequestHandler {
    engine: Arc<StorageEngine>,
    read_stream: ReadHalf<TcpStream>,
    response_tx: UnboundedSender<Response>,
}
impl RequestHandler {
    async fn run_once(&mut self) -> Result<()> {
        let c = &mut self.read_stream;
        let magic = io::read_u32(c).await?;
        if magic != 0x25609513 {
            strerror("Invalid request magic")?;
        }
        let _flags = io::read_u16(c).await?;
        let typ = io::read_u16(c).await?;
        let handle = io::read_u64(c).await?;
        let offset = io::read_u64(c).await?;
        let length = io::read_u32(c).await?;

        let request_id = handle;
        let req = match typ {
            NBD_CMD_READ => {
                IORequest::Read {
                    offset,
                    length,
                }
            },
            NBD_CMD_WRITE => {
                let mut buf = vec![0; length as usize];
                let _ = c.read_exact(&mut buf).await;
                IORequest::Write {
                    payload: buf,
                    offset,
                    length,
                    fua: false,
                }
            },
            NBD_CMD_DISC => {
                IORequest::Unknown
            }
            NBD_CMD_FLUSH => {
                IORequest::Flush
            }
            NBD_CMD_TRIM | NBD_CMD_WRITE_ZEROES => {
                IORequest::Unknown
            }
            _ => {
                IORequest::Unknown
            }
        };
        let tx = self.response_tx.clone();
        let engine = Arc::clone(&self.engine);
        // tmp
        // tokio::spawn(async move {
            let resp = engine.call(req).await;
            let resp = Response { inner: resp, request_id };
            let _ = tx.send(resp);
        // });
        Ok(())
    }
    async fn run(mut self) {
        loop {
            let _ = self.run_once().await;
        }
    }
}
struct ResponseHandler {
    write_stream: WriteHalf<TcpStream>,
    response_rx: UnboundedReceiver<Response>,
}
impl ResponseHandler {
    async fn run_once(&mut self, resp: Response) -> Result<()> {
        let c = &mut self.write_stream;
        let handle = resp.request_id;
        match resp.inner {
            Ok(res) => {
                match res {
                    IOResponse::Ok => {
                        reply(c, 0, handle).await?;
                    },
                    IOResponse::Read { mut payload } => {
                        reply(c, 0, handle).await?;
                        let _ = c.write_all(&mut payload).await;
                    },
                }
            }
            Err(e) => {
                let e = e.raw_os_error().unwrap_or(5) as u32;
                let _ = reply(c, e, handle).await;
            }
        }
        Ok(())
    }
    async fn run(mut self) {
        while let Some(resp) = self.response_rx.recv().await {
            let _ = self.run_once(resp).await;
        }
    }
}
pub struct Server {
    export: Export
}
impl Server {
    pub fn new(export: Export) -> Self {
        Self {
            export,
        }
    }
    pub async fn serve(self, socket: SocketAddr, engine: impl StorageEngine) {
        let engine = Arc::new(engine);
        let mut listener = TcpListener::bind(socket).await.unwrap();
        while let Ok((mut stream, _)) = listener.accept().await {
            // Disable Nagle algorithm
            stream.set_nodelay(true).unwrap();
            match handshake(&mut stream, &self.export).await {
                Ok(_) => {
                    let (read_stream, write_stream) = tokio::io::split(stream);
                    let (response_tx, response_rx) = mpsc::unbounded_channel::<Response>();
                    let request_handler = RequestHandler {
                        engine: engine.clone(),
                        read_stream,
                        response_tx,
                    };
                    let response_handler = ResponseHandler {
                        write_stream,
                        response_rx,
                    };
                    let fut = async move {
                        let mut fut1 = tokio::spawn(request_handler.run()).fuse();
                        let mut fut2 = tokio::spawn(response_handler.run()).fuse();
                        select! {
                            _ = fut1 => {},
                            _ = fut2 => {},
                        }
                    };
                    tokio::spawn(fut);
                },
                Err(_) => {}
            }
        }
    }
}
pub const NBD_DEFAULT_PORT: u16 = 10809;