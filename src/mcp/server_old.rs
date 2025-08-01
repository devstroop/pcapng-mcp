use std::path::PathBuf;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use rmcp::{
    ServerHandler, 
    model::{
        CallToolRequest, CallToolResult, Content, ListToolsResult, 
        ServerCapabilities, Tool, ToolsCapability
    },
    transport::stdio::StdioTransport,
    ErrorData, RequestContext, RoleServer
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::pcapng::parser::PcapNGParser;
use crate::utils::errors::{PcapNGResult, PcapNGError};

// Tool parameter structures
#[derive(Debug, Deserialize, Serialize)]
pub struct ParseFileRequest {
    pub file_path: PathBuf,
    #[serde(default)]
    pub include_timing: bool,
    #[serde(default)]
    pub max_interfaces: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FilterPacketsRequest {
    pub file_path: PathBuf,
    pub protocol: Option<String>,
    pub source_ip: Option<String>,
    pub dest_ip: Option<String>,
    pub port: Option<u16>,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MetadataRequest {
    pub file_path: PathBuf,
    #[serde(default)]
    pub include_sections: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AnalyzeTimingRequest {
    pub file_path: PathBuf,
    #[serde(default)]
    pub interface_id: Option<u32>,
}

fn default_max_results() -> usize {
    1000
}

#[derive(Clone)]
pub struct PcapNGServerHandler {
    parser: Arc<PcapNGParser>,
}

impl PcapNGServerHandler {
    pub fn new() -> Self {
        Self {
            parser: Arc::new(PcapNGParser::new()),
        }
    }

    pub async fn start_stdio_server() -> Result<(), Box<dyn std::error::Error>> {
        let handler = Self::new();
        let transport = StdioTransport::new();
        
        println!("PcapNG MCP Server starting on stdio...");
        
        // Start the MCP server
        rmcp::serve(handler, transport).await?;
        
        Ok(())
    }

    // Convert our errors to MCP ErrorData
    fn to_mcp_error(&self, err: PcapNGError) -> ErrorData {
        match err {
            PcapNGError::FileError(msg) => ErrorData::invalid_params(msg, None),
            PcapNGError::ParseError(msg) => ErrorData::parse_error(msg, None), 
            PcapNGError::McpError(msg) => ErrorData::internal_error(msg, None),
        }
    }

    async fn handle_parse_file(&self, args: Value) -> Result<Vec<Content>, ErrorData> {
        let request: ParseFileRequest = serde_json::from_value(args)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid arguments: {}", e), None))?;
        
        let file_info = self.parser.parse_file(&request.file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let result = serde_json::to_string_pretty(&file_info)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(vec![Content::Text { text: result }])
    }

    async fn handle_get_metadata(&self, args: Value) -> Result<Vec<Content>, ErrorData> {
        let request: MetadataRequest = serde_json::from_value(args)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid arguments: {}", e), None))?;
        
        let metadata = self.parser.get_metadata(&request.file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let result = serde_json::to_string_pretty(&metadata)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(vec![Content::Text { text: result }])
    }

    async fn handle_list_interfaces(&self, args: Value) -> Result<Vec<Content>, ErrorData> {
        let request: MetadataRequest = serde_json::from_value(args)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid arguments: {}", e), None))?;
        
        let interfaces = self.parser.list_interfaces(&request.file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let result = serde_json::to_string_pretty(&interfaces)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(vec![Content::Text { text: result }])
    }

    async fn handle_filter_packets(&self, args: Value) -> Result<Vec<Content>, ErrorData> {
        let request: FilterPacketsRequest = serde_json::from_value(args)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid arguments: {}", e), None))?;
        
        // Get basic file info first
        let file_info = self.parser.parse_file(&request.file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        // Create filter summary
        let filter_summary = json!({
            "file_path": request.file_path,
            "total_packets_in_file": file_info.total_packets,
            "applied_filters": {
                "protocol": request.protocol,
                "source_ip": request.source_ip,
                "dest_ip": request.dest_ip,
                "port": request.port
            },
            "max_results": request.max_results,
            "note": "Advanced packet filtering will be implemented in future versions"
        });
        
        let result = serde_json::to_string_pretty(&filter_summary)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(vec![Content::Text { text: result }])
    }

    async fn handle_analyze_timing(&self, args: Value) -> Result<Vec<Content>, ErrorData> {
        let request: AnalyzeTimingRequest = serde_json::from_value(args)
            .map_err(|e| ErrorData::invalid_params(format!("Invalid arguments: {}", e), None))?;
        
        // Get file info for timing analysis
        let file_info = self.parser.parse_file(&request.file_path).await
            .map_err(|e| self.to_mcp_error(e))?;
        
        let timing_analysis = json!({
            "file_path": request.file_path,
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
            "interface_filter": request.interface_id
        });
        
        let result = serde_json::to_string_pretty(&timing_analysis)
            .map_err(|e| ErrorData::internal_error(format!("Serialization error: {}", e), None))?;
        
        Ok(vec![Content::Text { text: result }])
    }
}

impl ServerHandler for PcapNGServerHandler {
    async fn list_tools(
        &self,
        _params: Option<rmcp::model::PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = vec![
            Tool {
                name: "parse_file".into(),
                description: Some("Parse a PcapNG or PCAP file and return comprehensive information including packet counts, timing, and interface details".into()),
                input_schema: Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PcapNG or PCAP file to parse"
                        },
                        "include_timing": {
                            "type": "boolean",
                            "description": "Whether to include detailed timing analysis",
                            "default": false
                        },
                        "max_interfaces": {
                            "type": "integer",
                            "description": "Maximum number of interfaces to process",
                            "minimum": 1
                        }
                    },
                    "required": ["file_path"]
                }).as_object().unwrap().clone()),
                annotations: None,
            },
            Tool {
                name: "get_metadata".into(),
                description: Some("Extract metadata information from a PcapNG file including section headers and interface details".into()),
                input_schema: Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PcapNG file to analyze"
                        },
                        "include_sections": {
                            "type": "boolean",
                            "description": "Whether to include section header details",
                            "default": false
                        }
                    },
                    "required": ["file_path"]
                }).as_object().unwrap().clone()),
                annotations: None,
            },
            Tool {
                name: "list_interfaces".into(),
                description: Some("List all network interfaces found in a PcapNG file with their properties".into()),
                input_schema: Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PcapNG file to analyze"
                        }
                    },
                    "required": ["file_path"]
                }).as_object().unwrap().clone()),
                annotations: None,
            },
            Tool {
                name: "filter_packets".into(),
                description: Some("Filter packets from a PcapNG file based on protocol, IP addresses, or ports".into()),
                input_schema: Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PcapNG file to filter"
                        },
                        "protocol": {
                            "type": "string",
                            "description": "Protocol to filter by (e.g., TCP, UDP, ICMP)",
                            "enum": ["TCP", "UDP", "ICMP", "ARP", "IPv4", "IPv6"]
                        },
                        "source_ip": {
                            "type": "string",
                            "description": "Source IP address to filter by (IPv4 or IPv6)"
                        },
                        "dest_ip": {
                            "type": "string",
                            "description": "Destination IP address to filter by (IPv4 or IPv6)"
                        },
                        "port": {
                            "type": "integer",
                            "description": "Port number to filter by (for TCP/UDP packets)",
                            "minimum": 1,
                            "maximum": 65535
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                            "default": 1000,
                            "minimum": 1,
                            "maximum": 10000
                        }
                    },
                    "required": ["file_path"]
                }).as_object().unwrap().clone()),
                annotations: None,
            },
            Tool {
                name: "analyze_timing".into(),
                description: Some("Analyze packet timing and traffic patterns in a PcapNG file".into()),
                input_schema: Arc::new(json!({
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the PcapNG file to analyze"
                        },
                        "interface_id": {
                            "type": "integer",
                            "description": "Specific interface ID to analyze (optional)",
                            "minimum": 0
                        }
                    },
                    "required": ["file_path"]
                }).as_object().unwrap().clone()),
                annotations: None,
            },
        ];

        Ok(ListToolsResult { tools })
    }

    async fn call_tool(
        &self,
        request: CallToolRequest,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let content = match request.params.name.as_ref() {
            "parse_file" => self.handle_parse_file(request.params.arguments.unwrap_or_default()).await?,
            "get_metadata" => self.handle_get_metadata(request.params.arguments.unwrap_or_default()).await?,
            "list_interfaces" => self.handle_list_interfaces(request.params.arguments.unwrap_or_default()).await?,
            "filter_packets" => self.handle_filter_packets(request.params.arguments.unwrap_or_default()).await?,
            "analyze_timing" => self.handle_analyze_timing(request.params.arguments.unwrap_or_default()).await?,
            _ => return Err(ErrorData::method_not_found::<&str>()),
        };

        Ok(CallToolResult {
            content,
            is_error: Some(false),
        })
    }

    fn get_server_capabilities(&self) -> ServerCapabilities {
        ServerCapabilities {
            tools: Some(ToolsCapability {
                list_changed: Some(false),
            }),
            ..Default::default()
        }
    }
}
