use byteorder::{BigEndian as BE, ByteOrder};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use std::io::Result;

pub async fn read_u16<R: AsyncRead + Unpin>(r: &mut R) -> Result<u16> {
    let mut buf = [0;2];
    r.read_exact(&mut buf).await?;
    Ok(BE::read_u16(&buf))
}
pub async fn read_u32<R: AsyncRead + Unpin>(r: &mut R) -> Result<u32> {
    let mut buf = [0;4];
    r.read_exact(&mut buf).await?;
    Ok(BE::read_u32(&buf))
}
pub async fn read_u64<R: AsyncRead + Unpin>(r: &mut R) -> Result<u64> {
    let mut buf = [0;8];
    r.read_exact(&mut buf).await?;
    Ok(BE::read_u64(&buf))
}
pub async fn write_u16<W: AsyncWrite + Unpin>(w: &mut W, x: u16) -> Result<()> {
    let mut buf = [0;2];
    BE::write_u16(&mut buf, x);
    w.write_all(&mut buf).await
}
pub async fn write_u32<W: AsyncWrite + Unpin>(w: &mut W, x: u32) -> Result<()> {
    let mut buf = [0;4];
    BE::write_u32(&mut buf, x);
    w.write_all(&mut buf).await
}
pub async fn write_u64<W: AsyncWrite + Unpin>(w: &mut W, x: u64) -> Result<()> {
    let mut buf = [0;8];
    BE::write_u64(&mut buf, x);
    w.write_all(&mut buf).await
}