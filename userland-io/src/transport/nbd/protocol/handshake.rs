use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io::Result;
use super::consts::*;
use super::io;

#[derive(Debug, Default, Hash, Eq, PartialEq, Ord, PartialOrd, Clone)]
pub struct Export {
    /// Size of the underlying data, in bytes
    pub size: u64,
    /// Tell client it's readonly
    pub readonly: bool,
    /// Tell that NBD_CMD_RESIZE should be supported. Not implemented in this library currently
    pub resizeable: bool,
    /// Tell that the exposed device has slow seeks, hence clients should use elevator algorithm
    pub rotational: bool,
    /// Tell that NBD_CMD_TRIM operation is supported. Not implemented in this library currently
    pub send_trim: bool,
    /// Tell that NBD_CMD_FLUSH may be sent
    pub send_flush: bool,
}

fn strerror(s: &'static str) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::InvalidData, s))
}

async fn reply<IO: AsyncWrite + AsyncRead + Unpin>(c: &mut IO, clopt: u32, rtype: u32, data: &[u8]) -> Result<()> {
    io::write_u64(c, 0x3e889045565a9).await?;
    io::write_u32(c, clopt).await?;
    io::write_u32(c, rtype).await?;
    io::write_u32(c, data.len() as u32).await?;
    c.write_all(data).await?;
    c.flush().await?;
    Ok(())
}

/// Ignores incoming export name, accepts everything
/// Export name is ignored, currently only one export is supported
pub async fn handshake<IO: AsyncWrite + AsyncRead + Unpin>(c: &mut IO, export: &Export) -> Result<()> {
    //let hs_flags = NBD_FLAG_FIXED_NEWSTYLE;
    let hs_flags = NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES;

    c.write_all(b"NBDMAGIC").await?;
    c.write_all(b"IHAVEOPT").await?;
    io::write_u16(c, hs_flags).await?;
    c.flush().await?;

    let client_flags = io::read_u32(c).await?;

    if client_flags != NBD_FLAG_C_FIXED_NEWSTYLE
        && client_flags != (NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES)
    {
        strerror("Invalid client flag")?;
    }

    loop {
        let client_optmagic = io::read_u64(c).await?;

        if client_optmagic != 0x49484156454F5054 {
            // IHAVEOPT
            strerror("Invalid client optmagic")?;
        }

        let clopt = io::read_u32(c).await?;
        let optlen = io::read_u32(c).await?;

        if optlen > 100000 {
            strerror("Suspiciously big option length")?;
        }

        let mut opt = vec![0; optlen as usize];
        c.read_exact(&mut opt).await?;

        match clopt {
            NBD_OPT_EXPORT_NAME => {
                io::write_u64(c, export.size).await?;
                let mut flags = NBD_FLAG_HAS_FLAGS;
                if export.readonly {
                    flags |= NBD_FLAG_READ_ONLY
                } else {
                    flags |= NBD_FLAG_SEND_FLUSH
                };
                if export.resizeable {
                    flags |= NBD_FLAG_SEND_RESIZE
                };
                if export.rotational {
                    flags |= NBD_FLAG_ROTATIONAL
                };
                if export.send_trim {
                    flags |= NBD_FLAG_SEND_TRIM
                };
                io::write_u16(c, flags).await?;
                if client_flags & NBD_FLAG_C_NO_ZEROES == 0 {
                    c.write_all(&[0; 124]).await?;
                }
                c.flush().await?;
                return Ok(());
            }
            NBD_OPT_ABORT => {
                reply(c, clopt, NBD_REP_ACK, b"").await?;
                strerror("Client abort")?;
            }
            NBD_OPT_LIST => {
                if optlen != 0 {
                    strerror("NBD_OPT_LIST with content")?;
                }

                reply(c, clopt, NBD_REP_SERVER, b"\x00\x00\x00\x07rustnbd").await?;
                reply(c, clopt, NBD_REP_ACK, b"").await?;
            }
            NBD_OPT_STARTTLS => {
                strerror("TLS not supported")?;
            }
            NBD_OPT_INFO => {
                reply(c, clopt, NBD_REP_ERR_UNSUP, b"").await?;
            }
            NBD_OPT_GO => {
                reply(c, clopt, NBD_REP_ERR_UNSUP, b"").await?;
            }
            // TODO
            // Will be supported for returning chunk stream from read
            NBD_OPT_STRUCTURED_REPLY => {
                reply(c, clopt, NBD_REP_ERR_UNSUP, b"").await?;
            }
            _ => {
                strerror("Invalid client option type")?;
            }
        }
    }
}