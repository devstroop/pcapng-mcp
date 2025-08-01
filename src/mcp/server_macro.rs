use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use rmcp::{mcp_tool, mcp_server, ErrorData, content::Content};
use crate::pcapng::parser::PcapNGParser;
use crate::utils::errors::{PcapNGError};

// Tool parameter structures
#[derive(Debug, Deserialize, Serialize)]
pub struct ParseFileRequest {
    pub file_path: String,
    pub include_timing: Option<bool>,
    pub include_interfaces: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetMetadataRequest {
    pub file_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListInterfacesRequest {
    pub file_path: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FilterPacketsRequest {
    pub file_path: String,
    pub protocol: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub port: Option<u16>,
    pub max_results: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnalyzeTimingRequest {
    pub file_path: String,
    pub interface_id: Option<u32>,
}

// Server structure
#[mcp_server]
pub struct PcapNGServer {
    parser: PcapNGParser,
}

impl PcapNGServer {
    pub fn new() -> Self {
        Self {
            parser: PcapNGParser::new(),
        }
    }

    fn to_mcp_error(&self, err: PcapNGError) -> ErrorData {
        match err {
            PcapNGError::McpError(msg) => ErrorData::internal_error(msg, None),
            _ => ErrorData::internal_error(format!("Parse error: {}", err), None),
        }
    }
}

#[mcp_tool]
impl PcapNGServer {
    /// Parse a PcapNG or PCAP file and return comprehensive information including packet counts, timing, and interface details
    async fn parse_file(
        &self,
        #[description("Path to the PcapNG or PCAP file to parse")] file_path: String,
        #[description("Include detailed timing analysis in the output")] include_timing: Option<bool>,
        #[description("Include interface details in the output")] include_interfaces: Option<bool>,
    ) -> Result<Content, ErrorData> {
        let file_info = self.parser.parse_file(&file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let mut result = json!({
            "file_path": file_path,
            "total_packets": file_info.total_packets,
            "file_size": file_info.file_size,
            "format": file_info.format,
        });
        
        if include_timing.unwrap_or(false) {
            result["timing"] = json!({
                "capture_duration": file_info.capture_duration,
                "first_packet": file_info.first_packet_time,
                "last_packet": file_info.last_packet_time,
            });
        }
        
        if include_interfaces.unwrap_or(false) {
            result["interfaces"] = json!(file_info.interfaces);
        }
        
        let result_str = serde_json::to_string_pretty(&result)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(Content::text(result_str))
    }

    /// Get metadata information about a PcapNG or PCAP file
    async fn get_metadata(
        &self,
        #[description("Path to the PcapNG or PCAP file")] file_path: String,
    ) -> Result<Content, ErrorData> {
        let file_info = self.parser.parse_file(&file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let metadata = json!({
            "file_path": file_path,
            "format": file_info.format,
            "file_size": file_info.file_size,
            "total_packets": file_info.total_packets,
            "interface_count": file_info.interfaces.len(),
            "capture_duration": file_info.capture_duration,
        });
        
        let result = serde_json::to_string_pretty(&metadata)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(Content::text(result))
    }

    /// List all network interfaces found in a PcapNG or PCAP file
    async fn list_interfaces(
        &self,
        #[description("Path to the PcapNG or PCAP file")] file_path: String,
    ) -> Result<Content, ErrorData> {
        let file_info = self.parser.parse_file(&file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let interfaces_list = json!({
            "file_path": file_path,
            "interface_count": file_info.interfaces.len(),
            "interfaces": file_info.interfaces,
        });
        
        let result = serde_json::to_string_pretty(&interfaces_list)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(Content::text(result))
    }

    /// Filter packets from a PcapNG or PCAP file based on various criteria
    async fn filter_packets(
        &self,
        #[description("Path to the PcapNG or PCAP file")] file_path: String,
        #[description("Protocol filter (e.g., 'TCP', 'UDP', 'ICMP')")] protocol: Option<String>,
        #[description("Source IP address filter")] source_ip: Option<String>,
        #[description("Destination IP address filter")] dest_ip: Option<String>,
        #[description("Port number filter")] port: Option<u16>,
        #[description("Maximum number of results to return")] max_results: Option<usize>,
    ) -> Result<Content, ErrorData> {
        let file_info = self.parser.parse_file(&file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let filter_summary = json!({
            "file_path": file_path,
            "total_packets_in_file": file_info.total_packets,
            "applied_filters": {
                "protocol": protocol,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "port": port
            },
            "max_results": max_results,
            "note": "Advanced packet filtering will be implemented in future versions"
        });
        
        let result = serde_json::to_string_pretty(&filter_summary)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(Content::text(result))
    }

    /// Analyze timing characteristics of packets in a PcapNG or PCAP file
    async fn analyze_timing(
        &self,
        #[description("Path to the PcapNG or PCAP file")] file_path: String,
        #[description("Interface ID to analyze (optional)")] interface_id: Option<u32>,
    ) -> Result<Content, ErrorData> {
        let file_info = self.parser.parse_file(&file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let timing_analysis = json!({
            "file_path": file_path,
            "total_packets": file_info.total_packets,
            "capture_duration": file_info.capture_duration,
            "first_packet": file_info.first_packet_time,
            "last_packet": file_info.last_packet_time,
            "average_packets_per_second": if let Some(duration) = &file_info.capture_duration {
                if duration.as_secs() > 0 {
                    Some(file_info.total_packets as f64 / duration.as_secs_f64())
                } else {
                    None
                }
            } else {
                None
            },
            "interfaces": file_info.interfaces.len(),
            "interface_filter": interface_id
        });
        
        let result = serde_json::to_string_pretty(&timing_analysis)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(Content::text(result))
    }
}

pub async fn start_mcp_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let server = PcapNGServer::new();
    rmcp::serve_stdio(server).await?;
    Ok(())
}
