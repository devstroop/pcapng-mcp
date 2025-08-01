use std::path::Path;
use std::io::{self, BufRead, BufReader, Write};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
    let server = PcapNGServer::new();
    
    // Log to stderr so it doesn't interfere with MCP protocol
    eprintln!("🚀 PcapNG MCP Server starting...");
    
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = BufReader::new(stdin);
    
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        
        // Parse JSON-RPC request
        let request: Value = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(_) => {
                // Send error response for invalid JSON
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": "Parse error"
                    }
                });
                writeln!(stdout, "{}", error_response)?;
                stdout.flush()?;
                continue;
            }
        };
        
        let response = handle_request(&server, request).await;
        writeln!(stdout, "{}", response)?;
        stdout.flush()?;
    }
    
    Ok(())
}

async fn handle_request(server: &PcapNGServer, request: Value) -> Value {
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    
    match method {
        "initialize" => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "pcapng-mcp-server",
                        "version": "0.1.0"
                    }
                }
            })
        },
        "notifications/initialized" => {
            // Just acknowledge the notification, no response needed
            return json!(null);
        },
        "tools/list" => {
            let tools = json!([
                {
                    "name": "parse_pcapng_file",
                    "description": "Parse a PcapNG or PCAP file and return comprehensive information",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the PcapNG or PCAP file to parse"
                            }
                        },
                        "required": ["file_path"]
                    }
                },
                {
                    "name": "get_pcapng_metadata",
                    "description": "Get metadata information about a PcapNG or PCAP file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the PcapNG or PCAP file"
                            }
                        },
                        "required": ["file_path"]
                    }
                },
                {
                    "name": "list_pcapng_interfaces",
                    "description": "List all network interfaces found in a PcapNG or PCAP file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string",
                                "description": "Path to the PcapNG or PCAP file"
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            ]);
            
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "tools": tools
                }
            })
        },
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(json!({}));
            let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            
            let result = match tool_name {
                "parse_pcapng_file" => {
                    if let Some(file_path) = arguments.get("file_path").and_then(|f| f.as_str()) {
                        match server.parse_file(file_path).await {
                            Ok(content) => json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": content
                                    }
                                ]
                            }),
                            Err(e) => json!({
                                "error": {
                                    "code": -32000,
                                    "message": format!("Parse error: {}", e)
                                }
                            })
                        }
                    } else {
                        json!({
                            "error": {
                                "code": -32602,
                                "message": "Missing required parameter: file_path"
                            }
                        })
                    }
                },
                "get_pcapng_metadata" => {
                    if let Some(file_path) = arguments.get("file_path").and_then(|f| f.as_str()) {
                        match server.get_metadata(file_path).await {
                            Ok(content) => json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": content
                                    }
                                ]
                            }),
                            Err(e) => json!({
                                "error": {
                                    "code": -32000,
                                    "message": format!("Metadata error: {}", e)
                                }
                            })
                        }
                    } else {
                        json!({
                            "error": {
                                "code": -32602,
                                "message": "Missing required parameter: file_path"
                            }
                        })
                    }
                },
                "list_pcapng_interfaces" => {
                    if let Some(file_path) = arguments.get("file_path").and_then(|f| f.as_str()) {
                        match server.list_interfaces(file_path).await {
                            Ok(content) => json!({
                                "content": [
                                    {
                                        "type": "text",
                                        "text": content
                                    }
                                ]
                            }),
                            Err(e) => json!({
                                "error": {
                                    "code": -32000,
                                    "message": format!("Interface listing error: {}", e)
                                }
                            })
                        }
                    } else {
                        json!({
                            "error": {
                                "code": -32602,
                                "message": "Missing required parameter: file_path"
                            }
                        })
                    }
                },
                _ => json!({
                    "error": {
                        "code": -32601,
                        "message": format!("Unknown tool: {}", tool_name)
                    }
                })
            };
            
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": result
            })
        },
        _ => {
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": -32601,
                    "message": format!("Unknown method: {}", method)
                }
            })
        }
    }
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
