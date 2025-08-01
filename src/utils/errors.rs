use thiserror::Error;

#[derive(Debug, Error)]
pub enum PcapNGError {
    #[error("File not found: {0}")]
    FileNotFound(String),
    
    #[error("File error: {0}")]
    FileError(String),
    
    #[error("Invalid PcapNG format: {0}")]
    InvalidFormat(String),
    
    #[error("Parsing error: {0}")]
    ParseError(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("MCP error: {0}")]
    McpError(String),
    
    #[error("Invalid timestamp: {0}")]
    TimestampError(String),
    
    #[error("Unsupported link type: {0}")]
    UnsupportedLinkType(u16),
}

pub type PcapNGResult<T> = std::result::Result<T, PcapNGError>;
pub type Result<T> = std::result::Result<T, PcapNGError>;
