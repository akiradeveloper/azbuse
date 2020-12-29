use std::io::Result;
use tokio::io::{AsyncWrite};
use super::io;

pub async fn reply<IO: AsyncWrite + Unpin>(c: &mut IO, error: u32, handle: u64) -> Result<()> {
    io::write_u32(c, 0x67446698).await?;
    io::write_u32(c, error).await?;
    io::write_u64(c, handle).await?;
    Ok(())
}