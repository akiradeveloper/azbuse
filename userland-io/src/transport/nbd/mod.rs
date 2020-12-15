use std::net::SocketAddr;
use tokio::net::{TcpStream, TcpListener};
use tokio::stream::StreamExt;
use tokio::sync::mpsc::{self, Sender, Receiver};
use tokio::io::{ReadHalf, WriteHalf, AsyncWriteExt, AsyncReadExt};
use crate::{Request, Response, IORequest, IOResponse};
use std::io::Result;
use protocol::io;
use futures::select;
use futures::future::FutureExt;

mod protocol;
use protocol::handshake::*;
use protocol::consts::*;
use protocol::transmission::reply;

pub use protocol::handshake::Export;

fn strerror(s: &'static str) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, s))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Context {
    handle: u64,
}

struct RequestHandler {
    read_stream: ReadHalf<TcpStream>,
    request_tx: Sender<Request>,
    response_tx: Sender<Response>,
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

        let context = Context {
            handle,
        };
        let context = rmp_serde::to_vec(&context).unwrap();

        match typ {
            NBD_CMD_READ => {
                let req = Request {
                    inner: IORequest::Read {
                        offset,
                        length,
                    },
                    tx: self.response_tx.clone(),
                    context,
                };
                let _ = self.request_tx.send(req).await;
            },
            NBD_CMD_WRITE => {
                let mut buf = vec![0; length as usize];
                let _ = c.read_exact(&mut buf).await;
                let req = Request {
                    inner: IORequest::Write {
                        payload: buf,
                        offset,
                        length,
                        fua: false,
                    },
                    tx: self.response_tx.clone(),
                    context,
                };
                let _ = self.request_tx.send(req).await;
            },
            NBD_CMD_DISC => {
                return Ok(())
            }
            NBD_CMD_FLUSH => {
                let req = Request {
                    inner: IORequest::Flush,
                    tx: self.response_tx.clone(),
                    context,
                };
                let _ = self.request_tx.send(req).await;
            }
            NBD_CMD_TRIM | NBD_CMD_WRITE_ZEROES => {
                let req = Request {
                    // Not implemented
                    inner: IORequest::Echo(38),
                    tx: self.response_tx.clone(),
                    context,
                };
                let _ = self.request_tx.send(req).await;
            }
            _ => {}
        }
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
    response_rx: Receiver<Response>,
}
impl ResponseHandler {
    async fn run_once(&mut self, resp: Response) -> Result<()> {
        let c = &mut self.write_stream;
        let context: Context = rmp_serde::from_slice(&resp.context).unwrap();
        let handle = context.handle;
        match resp.inner {
            Ok(IOResponse::Ok) => {
                reply(c, 0, handle).await?;
            },
            Ok(IOResponse::Read { mut payload }) => {
                reply(c, 0, handle).await?;
                let _ = c.write_all(&mut payload).await;
            },
            Ok(IOResponse::Echo(n)) => {
                let _ = reply(c, n, handle).await;
            },
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
    request_tx: Sender<Request>,
    export: Export
}
impl Server {
    pub fn new(request_tx: Sender<Request>, export: Export) -> Self {
        Self {
            request_tx,
            export,
        }
    }
    pub async fn serve(self, socket: SocketAddr) {
        let mut listener = TcpListener::bind(socket).await.unwrap();
        while let Some(conn) = listener.next().await {
            match conn {
                Ok(mut stream) => {
                    match handshake(&mut stream, &self.export).await {
                        Ok(_) => {
                            let (read_stream, write_stream) = tokio::io::split(stream);
                            let (response_tx, response_rx) = mpsc::channel::<Response>(64);
                            let request_handler = RequestHandler {
                                read_stream,
                                request_tx: self.request_tx.clone(),
                                response_tx,
                            };
                            let response_handler = ResponseHandler {
                                write_stream,
                                response_rx,
                            };
                            let fut = async move {
                                let fut1 = tokio::spawn(request_handler.run()).fuse();
                                let fut2 = tokio::spawn(response_handler.run()).fuse();
                                futures::pin_mut!(fut1, fut2);
                                select! {
                                    _ = fut1 => {},
                                    _ = fut2 => {},
                                }
                            };
                            tokio::spawn(fut);
                        },
                        Err(_) => {}
                    }
                },
                Err(_) => {},
            }
        }
    }
}
pub const NBD_DEFAULT_PORT: u16 = 10809;