use std::path::Path;
use std::io::BufReader;
use std::fs::File;
use pcap_parser::{
    LegacyPcapReader, PcapNGReader, 
    traits::PcapReaderIterator,
    PcapError,
    pcapng::Block,
};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

use crate::utils::errors::{PcapNGError, PcapNGResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub file_type: String,
    pub file_size: u64,
    pub total_packets: u64,
    pub interfaces: Vec<InterfaceInfo>,
    pub capture_duration: Option<std::time::Duration>,
    pub first_packet_time: Option<DateTime<Utc>>,
    pub last_packet_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub id: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub link_type: String,
    pub snap_len: u32,
    pub packet_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub interface_id: Option<u32>,
    pub timestamp: Option<DateTime<Utc>>,
    pub captured_len: u32,
    pub original_len: u32,
    pub data_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub section_info: Option<SectionInfo>,
    pub interfaces: Vec<InterfaceInfo>,
    pub total_blocks: u64,
    pub file_comments: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub byte_order_magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub section_length: Option<u64>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalysis {
    pub total_duration: Option<std::time::Duration>,
    pub packet_rate: f64,
    pub average_interval: std::time::Duration,
    pub min_interval: Option<std::time::Duration>,
    pub max_interval: Option<std::time::Duration>,
}

pub struct PcapNGParser;

impl PcapNGParser {
    pub fn new() -> Self {
        Self
    }

    pub async fn parse_file(&self, file_path: &Path) -> PcapNGResult<FileInfo> {
        let file = File::open(file_path)
            .map_err(|e| PcapNGError::FileError(format!("Cannot open file: {}", e)))?;
        
        let file_size = file.metadata()
            .map_err(|e| PcapNGError::FileError(format!("Cannot get file metadata: {}", e)))?
            .len();

        let mut reader = BufReader::new(file);
        
        // Try to detect file format by reading the first few bytes
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut reader, &mut buf)
            .map_err(|e| PcapNGError::ParseError(format!("Cannot read file header: {}", e)))?;
        
        // Reset reader
        let file = File::open(file_path)
            .map_err(|e| PcapNGError::FileError(format!("Cannot reopen file: {}", e)))?;
        let reader = BufReader::new(file);

        // Check magic bytes
        match u32::from_le_bytes(buf) {
            0x0A0D0D0A => self.parse_pcapng_file(reader).await,
            0xA1B2C3D4 | 0xD4C3B2A1 => self.parse_pcap_file(reader).await,
            _ => Err(PcapNGError::ParseError("Unknown file format".to_string())),
        }
        .map(|mut info| {
            info.file_size = file_size;
            info
        })
    }

    async fn parse_pcapng_file(&self, reader: BufReader<File>) -> PcapNGResult<FileInfo> {
        let mut pcapng_reader = PcapNGReader::new(65536, reader)
            .map_err(|e| PcapNGError::ParseError(format!("Cannot create PcapNG reader: {:?}", e)))?;

        let mut interfaces = Vec::new();
        let mut total_packets = 0u64;
        let mut first_packet_time = None;
        let mut last_packet_time = None;

        loop {
            match pcapng_reader.next() {
                Ok((offset, block)) => {
                    match block {
                        pcap_parser::PcapBlockOwned::NG(ng_block) => {
                            match ng_block {
                                Block::InterfaceDescription(idb) => {
                                    let interface_info = InterfaceInfo {
                                        id: interfaces.len() as u32,
                                        name: None, // TODO: Fix if_name() method call
                                        description: None, // TODO: Fix if_description() method call  
                                        link_type: format!("{}", idb.linktype),
                                        snap_len: idb.snaplen,
                                        packet_count: 0, // Will be updated as we process packets
                                    };
                                    interfaces.push(interface_info);
                                }
                                Block::EnhancedPacket(epb) => {
                                    total_packets += 1;
                                    
                                    // Convert timestamps (this is simplified)
                                    let timestamp = {
                                        let timestamp_raw = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
                                        // Note: This is a simplified timestamp conversion
                                        Some(DateTime::from_timestamp(timestamp_raw as i64 / 1_000_000, 0).unwrap_or_else(|| Utc::now()))
                                    };

                                    if first_packet_time.is_none() {
                                        first_packet_time = timestamp;
                                    }
                                    last_packet_time = timestamp;
                                }
                                Block::SimplePacket(_) => {
                                    total_packets += 1;
                                }
                                _ => {}
                            }
                        }
                        _ => {
                            // Handle other block types or skip them
                        }
                    }
                    pcapng_reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    pcapng_reader.refill()
                        .map_err(|e| PcapNGError::ParseError(format!("Cannot refill buffer: {:?}", e)))?;
                }
                Err(e) => return Err(PcapNGError::ParseError(format!("Parse error: {:?}", e))),
            }
        }

        let capture_duration = if let (Some(first), Some(last)) = (first_packet_time, last_packet_time) {
            if last > first {
                Some(std::time::Duration::from_secs((last - first).num_seconds() as u64))
            } else {
                None
            }
        } else {
            None
        };

        Ok(FileInfo {
            file_type: "PcapNG".to_string(),
            file_size: 0, // Will be set by caller
            total_packets,
            interfaces,
            capture_duration,
            first_packet_time,
            last_packet_time,
        })
    }

    async fn parse_pcap_file(&self, reader: BufReader<File>) -> PcapNGResult<FileInfo> {
        let mut pcap_reader = LegacyPcapReader::new(65536, reader)
            .map_err(|e| PcapNGError::ParseError(format!("Cannot create PCAP reader: {:?}", e)))?;

        // Note: Legacy PCAP readers don't expose header directly in this version
        let interface_info = InterfaceInfo {
            id: 0,
            name: None,
            description: Some("Legacy PCAP interface".to_string()),
            link_type: "Unknown".to_string(), // We'll update this if we can determine it
            snap_len: 65535, // Default
            packet_count: 0,
        };

        let mut total_packets = 0u64;
        let first_packet_time = None;
        let last_packet_time = None;

        loop {
            match pcap_reader.next() {
                Ok((offset, _packet)) => {
                    total_packets += 1;
                    // Note: Legacy PCAP timestamp handling would go here
                    pcap_reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    pcap_reader.refill()
                        .map_err(|e| PcapNGError::ParseError(format!("Cannot refill buffer: {:?}", e)))?;
                }
                Err(e) => return Err(PcapNGError::ParseError(format!("Parse error: {:?}", e))),
            }
        }

        Ok(FileInfo {
            file_type: "PCAP".to_string(),
            file_size: 0, // Will be set by caller
            total_packets,
            interfaces: vec![interface_info],
            capture_duration: None,
            first_packet_time,
            last_packet_time,
        })
    }

    pub async fn get_metadata(&self, file_path: &Path) -> PcapNGResult<FileMetadata> {
        let file = File::open(file_path)
            .map_err(|e| PcapNGError::FileError(format!("Cannot open file: {}", e)))?;
        
        let mut reader = BufReader::new(file);
        
        // Try to detect file format
        let mut buf = [0u8; 4];
        std::io::Read::read_exact(&mut reader, &mut buf)
            .map_err(|e| PcapNGError::ParseError(format!("Cannot read file header: {}", e)))?;
        
        match u32::from_le_bytes(buf) {
            0x0A0D0D0A => {
                // Reset and parse as PcapNG
                let file = File::open(file_path)
                    .map_err(|e| PcapNGError::FileError(format!("Cannot reopen file: {}", e)))?;
                let reader = BufReader::new(file);
                self.get_pcapng_metadata(reader).await
            }
            _ => {
                // For legacy PCAP, return minimal metadata
                Ok(FileMetadata {
                    section_info: None,
                    interfaces: vec![],
                    total_blocks: 0,
                    file_comments: vec!["Legacy PCAP file".to_string()],
                })
            }
        }
    }

    async fn get_pcapng_metadata(&self, reader: BufReader<File>) -> PcapNGResult<FileMetadata> {
        let mut pcapng_reader = PcapNGReader::new(65536, reader)
            .map_err(|e| PcapNGError::ParseError(format!("Cannot create PcapNG reader: {:?}", e)))?;

        let mut section_info = None;
        let mut interfaces = Vec::new();
        let mut total_blocks = 0u64;
        let file_comments = Vec::new();

        loop {
            match pcapng_reader.next() {
                Ok((offset, block)) => {
                    total_blocks += 1;
                    
                    match block {
                        pcap_parser::PcapBlockOwned::NG(ng_block) => {
                            match ng_block {
                                Block::SectionHeader(shb) => {
                                    section_info = Some(SectionInfo {
                                        byte_order_magic: shb.bom,
                                        version_major: shb.major_version,
                                        version_minor: shb.minor_version,
                                        section_length: Some(shb.section_len as u64),
                                        options: vec![], // Simplified
                                    });
                                }
                                Block::InterfaceDescription(idb) => {
                                    let interface_info = InterfaceInfo {
                                        id: interfaces.len() as u32,
                                        name: None, // TODO: Fix if_name() method call
                                        description: None, // TODO: Fix if_description() method call
                                        link_type: format!("{}", idb.linktype),
                                        snap_len: idb.snaplen,
                                        packet_count: 0,
                                    };
                                    interfaces.push(interface_info);
                                }
                                _ => {}
                            }
                        }
                        _ => {
                            // Handle other block types or skip them
                        }
                    }
                    pcapng_reader.consume(offset);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    pcapng_reader.refill()
                        .map_err(|e| PcapNGError::ParseError(format!("Cannot refill buffer: {:?}", e)))?;
                }
                Err(e) => return Err(PcapNGError::ParseError(format!("Parse error: {:?}", e))),
            }
        }

        Ok(FileMetadata {
            section_info,
            interfaces,
            total_blocks,
            file_comments,
        })
    }

    pub async fn list_interfaces(&self, file_path: &Path) -> PcapNGResult<Vec<InterfaceInfo>> {
        let file_info = self.parse_file(file_path).await?;
        Ok(file_info.interfaces)
    }

    pub async fn analyze_timing(&self, file_path: &Path) -> PcapNGResult<TimingAnalysis> {
        let file_info = self.parse_file(file_path).await?;
        
        let total_duration = file_info.capture_duration.unwrap_or_default();
        let packet_rate = if total_duration.as_secs() > 0 {
            file_info.total_packets as f64 / total_duration.as_secs_f64()
        } else {
            0.0
        };
        
        let average_interval = if file_info.total_packets > 1 {
            std::time::Duration::from_nanos(
                (total_duration.as_nanos() / (file_info.total_packets - 1) as u128) as u64
            )
        } else {
            std::time::Duration::default()
        };

        Ok(TimingAnalysis {
            total_duration: Some(total_duration),
            packet_rate,
            average_interval,
            min_interval: None, // Would require detailed packet analysis
            max_interval: None, // Would require detailed packet analysis
        })
    }
}
