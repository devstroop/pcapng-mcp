use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ParseFileArgs {
    pub file_path: String,
    pub include_packet_data: Option<bool>,
    pub max_packets: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterPacketsArgs {
    pub file_path: String,
    pub interface_id: Option<u32>,
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    pub min_size: Option<u32>,
    pub max_size: Option<u32>,
    pub max_results: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetStatsArgs {
    pub file_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ListInterfacesArgs {
    pub file_path: String,
}

pub fn get_tool_definitions() -> serde_json::Value {
    serde_json::json!([
        {
            "name": "parse_pcapng_file",
            "description": "Parse a PcapNG or PCAP file and extract metadata, interface information, and packet summaries. This tool can handle both PcapNG and legacy PCAP formats.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the PcapNG or PCAP file to parse"
                    },
                    "include_packet_data": {
                        "type": "boolean",
                        "description": "Include packet data preview (first 32 bytes as hex). Default: false"
                    },
                    "max_packets": {
                        "type": "integer",
                        "description": "Maximum number of packets to process. Default: 1000",
                        "minimum": 1,
                        "maximum": 100000
                    }
                },
                "required": ["file_path"]
            }
        },
        {
            "name": "filter_packets",
            "description": "Filter packets from a PcapNG/PCAP file based on various criteria like interface, time range, and packet size.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the PcapNG or PCAP file"
                    },
                    "interface_id": {
                        "type": "integer",
                        "description": "Filter by interface ID (0-based)",
                        "minimum": 0
                    },
                    "start_time": {
                        "type": "string",
                        "description": "Filter packets after this time (ISO 8601 format, e.g., '2024-01-01T00:00:00Z')"
                    },
                    "end_time": {
                        "type": "string",
                        "description": "Filter packets before this time (ISO 8601 format)"
                    },
                    "min_size": {
                        "type": "integer",
                        "description": "Minimum packet size in bytes",
                        "minimum": 0
                    },
                    "max_size": {
                        "type": "integer",
                        "description": "Maximum packet size in bytes",
                        "minimum": 0
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum number of filtered packets to return. Default: 1000",
                        "minimum": 1,
                        "maximum": 10000
                    }
                },
                "required": ["file_path"]
            }
        },
        {
            "name": "get_file_statistics",
            "description": "Get comprehensive statistics about a PcapNG/PCAP file including packet counts, size distribution, time range, and per-interface statistics.",
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
            "name": "list_interfaces",
            "description": "List all network interfaces found in a PcapNG/PCAP file with their metadata and configuration.",
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
    ])
}
