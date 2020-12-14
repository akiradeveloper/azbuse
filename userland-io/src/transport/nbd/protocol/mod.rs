// This module is a minimum fork of rust-nbd https://github.com/vi/rust-nbd

pub mod handshake;
pub mod transmission;
pub mod io;

// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
pub mod consts {
    // Option Types
    pub const NBD_OPT_EXPORT_NAME: u32 = 1;
    pub const NBD_OPT_ABORT: u32 = 2;
    pub const NBD_OPT_LIST: u32 = 3;
    pub const NBD_OPT_PEEK_EXPORT: u32 = 4;
    pub const NBD_OPT_STARTTLS: u32 = 5;
    pub const NBD_OPT_INFO: u32 = 6;
    pub const NBD_OPT_GO: u32 = 7;
    pub const NBD_OPT_STRUCTURED_REPLY: u32 = 8;

    // Option Reply Types
    pub const NBD_REP_ACK: u32 = 1;
    pub const NBD_REP_SERVER: u32 = 2;
    pub const NBD_REP_INFO: u32 = 3;
    pub const NBD_REP_META_CONTEXT: u32 = 4;
    pub const NBD_REP_FLAG_ERROR: u32 = 1 << 31;
    pub const NBD_REP_ERR_UNSUP: u32 = 1 | NBD_REP_FLAG_ERROR;
    pub const NBD_REP_ERR_POLICY: u32 = 2 | NBD_REP_FLAG_ERROR;
    pub const NBD_REP_ERR_INVALID: u32 = 3 | NBD_REP_FLAG_ERROR;
    pub const NBD_REP_ERR_PLATFORM: u32 = 4 | NBD_REP_FLAG_ERROR;
    pub const NBD_REP_ERR_TLS_REQD: u32 = 5 | NBD_REP_FLAG_ERROR;
    pub const NBD_REP_ERR_UNKNOWN: u32 = 6 | NBD_REP_FLAG_ERROR;
    pub const NBD_REP_ERR_BLOCK_SIZE_REQD: u32 = 8 | NBD_REP_FLAG_ERROR;

    // Handshake (Server)
    pub const NBD_FLAG_FIXED_NEWSTYLE: u16 = 1 << 0;
    pub const NBD_FLAG_NO_ZEROES: u16 = 1 << 1;

    // Handshake (Client)
    pub const NBD_FLAG_C_FIXED_NEWSTYLE: u32 = NBD_FLAG_FIXED_NEWSTYLE as u32;
    pub const NBD_FLAG_C_NO_ZEROES: u32 = NBD_FLAG_NO_ZEROES as u32;

    // Info Types
    pub const NBD_INFO_EXPORT: u16 = 0;
    pub const NBD_INFO_NAME: u16 = 1;
    pub const NBD_INFO_DESCRIPTION: u16 = 2;
    pub const NBD_INFO_BLOCK_SIZE: u16 = 3;

    // Transmission Flags
    // This field of 16 bits is sent by the server after option haggling, or immediately after the handshake flags field in oldstyle negotiation.
    pub const NBD_FLAG_HAS_FLAGS: u16 = 1 << 0;
    pub const NBD_FLAG_READ_ONLY: u16 = 1 << 1;
    pub const NBD_FLAG_SEND_FLUSH: u16 = 1 << 2;
    pub const NBD_FLAG_SEND_FUA: u16 = 1 << 3;
    pub const NBD_FLAG_ROTATIONAL: u16 = 1 << 4;
    pub const NBD_FLAG_SEND_TRIM: u16 = 1 << 5;
    pub const NBD_FLAG_SEND_WRITE_ZEROES: u16 = 1 << 6;
    pub const NBD_FLAG_CAN_MULTI_CONN: u16 = 1 << 8;
    pub const NBD_FLAG_SEND_RESIZE: u16 = 1 << 9;

    // Request Flags
    // This field of 16 bits is sent by the client with every request and provides additional information to the server to execute the command. 
    pub const NBD_CMD_FLAG_FUA: u16 = 1 << 0;
    pub const NBD_CMD_FLAG_NO_HOLE: u16 = 1 << 1;
    pub const NBD_CMD_FLAG_FLAG_DF: u16 = 1 << 2;
    pub const NBD_CMD_FLAG_REQ_ONE: u16 = 1 << 3;
    pub const NBD_CMD_FLAG_FAST_ZERO: u16 = 1 << 4;

    // Request Types
    pub const NBD_CMD_READ: u16 = 0;
    pub const NBD_CMD_WRITE: u16 = 1;
    pub const NBD_CMD_DISC: u16 = 2;
    pub const NBD_CMD_FLUSH: u16 = 3;
    pub const NBD_CMD_TRIM: u16 = 4;
    pub const NBD_CMD_CACHE: u16 = 5;
    pub const NBD_CMD_WRITE_ZEROES: u16 = 6;
    pub const NBD_CMD_BLOCK_STATUS: u16 = 7;
    pub const NBD_CMD_RESIZE: u16 = 8;
}
