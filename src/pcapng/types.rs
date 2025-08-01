use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub hardware: Option<String>,
    pub os: Option<String>,
    pub application: Option<String>,
    pub byte_order: String,
    pub major_version: u16,
    pub minor_version: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceInfo {
    pub id: u32,
    pub name: Option<String>,
    pub description: Option<String>,
    pub link_type: u16,
    pub link_type_name: String,
    pub snap_length: u32,
    pub timestamp_resolution: u8,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub interface_id: u32,
    pub timestamp: DateTime<Utc>,
    pub captured_length: u32,
    pub original_length: u32,
    pub data_preview: Option<String>, // First N bytes as hex
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStatistics {
    pub file_path: String,
    pub file_size: u64,
    pub total_packets: usize,
    pub total_sections: usize,
    pub total_interfaces: usize,
    pub time_range: Option<TimeRange>,
    pub interface_stats: Vec<InterfaceStats>,
    pub packet_size_distribution: PacketSizeDistribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    pub duration_seconds: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    pub interface_id: u32,
    pub packet_count: usize,
    pub total_bytes: u64,
    pub avg_packet_size: f64,
    pub link_type: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSizeDistribution {
    pub min_size: u32,
    pub max_size: u32,
    pub avg_size: f64,
    pub size_buckets: Vec<SizeBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SizeBucket {
    pub range: String,
    pub count: usize,
    pub percentage: f64,
}

pub fn link_type_to_name(link_type: u16) -> String {
    match link_type {
        1 => "Ethernet".to_string(),
        105 => "IEEE 802.11".to_string(),
        127 => "IEEE 802.11 Radio".to_string(),
        9 => "PPP".to_string(),
        12 => "Raw IP".to_string(),
        113 => "Linux cooked".to_string(),
        _ => format!("Unknown ({})", link_type),
    }
}
