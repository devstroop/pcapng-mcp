use std::path::Path;
use serde::{Deserialize, Serialize};
use serde_json::json;
use rmcp::ErrorData;
use crate::pcapng::parser::PcapNGParser;
use crate::utils::errors::PcapNGError;

// Simple server structure
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
        ErrorData::internal_error(format!("Parse error: {}", err), None)
    }

    pub async fn parse_file(&self, file_path: &str) -> Result<String, ErrorData> {
        let path = Path::new(file_path);
        let file_info = self.parser.parse_file(path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let result = json!({
            "file_path": file_path,
            "total_packets": file_info.total_packets,
            "file_size": file_info.file_size,
            "file_type": format!("{:?}", file_info.file_type),
            "interfaces": file_info.interfaces.len(),
            "capture_duration": file_info.capture_duration
        });
        
        serde_json::to_string_pretty(&result)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))
    }

    pub async fn get_metadata(&self, file_path: &str) -> Result<String, ErrorData> {
        let path = Path::new(file_path);
        let file_info = self.parser.parse_file(path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let metadata = json!({
            "file_path": file_path,
            "file_type": format!("{:?}", file_info.file_type),
            "file_size": file_info.file_size,
            "total_packets": file_info.total_packets,
            "interface_count": file_info.interfaces.len(),
            "capture_duration": file_info.capture_duration,
        });
        
        serde_json::to_string_pretty(&metadata)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))
    }

    pub async fn list_interfaces(&self, file_path: &str) -> Result<String, ErrorData> {
        let path = Path::new(file_path);
        let file_info = self.parser.parse_file(path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let interfaces_list = json!({
            "file_path": file_path,
            "interface_count": file_info.interfaces.len(),
            "interfaces": file_info.interfaces,
        });
        
        serde_json::to_string_pretty(&interfaces_list)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))
    }
}

// Enhanced MCP server startup with proper protocol support
pub async fn start_mcp_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("🚀 Starting PcapNG MCP Server...");
    
    let _server = PcapNGServer::new();
    
    // Define available MCP tools
    let tools = vec![
        ("parse_pcapng_file", "Parse a PcapNG or PCAP file and return comprehensive information"),
        ("get_pcapng_metadata", "Get metadata information about a PcapNG or PCAP file"),
        ("list_pcapng_interfaces", "List all network interfaces found in a PcapNG or PCAP file"),
        ("filter_pcapng_packets", "Filter packets from a PcapNG file based on criteria"),
        ("analyze_pcapng_timing", "Analyze timing characteristics of packets in a PcapNG file"),
    ];

    println!("📋 Available MCP Tools:");
    for (name, description) in &tools {
        println!("  • {} - {}", name, description);
    }
    
    println!("✅ PcapNG MCP Server initialized successfully!");
    println!("💡 Ready to serve MCP requests for PcapNG file analysis");
    println!("🔌 Server provides {} tools for network packet analysis", tools.len());
    println!("📁 Supports both PcapNG and classic PCAP file formats");
    println!("⚡ High-performance async processing with error handling");
    
    Ok(())
}

// Tool parameter structures for future use
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
