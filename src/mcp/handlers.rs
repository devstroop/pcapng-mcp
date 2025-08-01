use crate::mcp::tools::*;
use crate::pcapng::{PcapNGParser, PcapNGAnalyzer};
use crate::utils::errors::*;
use chrono::{DateTime, Utc};
use tracing::{info, error};

// Simple internal ToolResult type for our handlers
#[derive(Debug)]
pub struct ToolResult {
    pub content: Vec<ToolResultContent>,
}

#[derive(Debug)]
pub enum ToolResultContent {
    Text { text: String },
}

impl ToolResult {
    pub fn new(content: Vec<ToolResultContent>) -> Self {
        Self { content }
    }
}

pub async fn handle_parse_file(args: serde_json::Value) -> Result<ToolResult> {
    let args: ParseFileArgs = serde_json::from_value(args)
        .map_err(|e| PcapNGError::JsonError(e))?;

    info!("Parsing file: {}", args.file_path);

    let mut parser = PcapNGParser::new(args.file_path.clone());
    
    match parser.parse_file(
        args.max_packets,
        args.include_packet_data.unwrap_or(false)
    ).await {
        Ok(_) => {
            let result = serde_json::json!({
                "success": true,
                "file_info": {
                    "path": args.file_path,
                    "sections": parser.sections.len(),
                    "interfaces": parser.interfaces.len(),
                    "total_packets": parser.packets.len()
                },
                "sections": parser.sections,
                "interfaces": parser.interfaces,
                "packets": if args.include_packet_data.unwrap_or(false) {
                    parser.packets.into_iter()
                        .take(args.max_packets.unwrap_or(1000))
                        .collect::<Vec<_>>()
                } else {
                    vec![]
                }
            });

            Ok(ToolResult::new(vec![ToolResultContent::Text {
                text: serde_json::to_string_pretty(&result)
                    .map_err(|e| PcapNGError::JsonError(e))?,
            }]))
        },
        Err(e) => {
            error!("Failed to parse file: {:?}", e);
            let error_result = serde_json::json!({
                "success": false,
                "error": format!("{}", e),
                "file_path": args.file_path
            });

            Ok(ToolResult::new(vec![ToolResultContent::Text {
                text: serde_json::to_string_pretty(&error_result)
                    .map_err(|e| PcapNGError::JsonError(e))?,
            }]))
        }
    }
}

pub async fn handle_filter_packets(args: serde_json::Value) -> Result<ToolResult> {
    let args: FilterPacketsArgs = serde_json::from_value(args)
        .map_err(|e| PcapNGError::JsonError(e))?;

    info!("Filtering packets from file: {}", args.file_path);

    let mut parser = PcapNGParser::new(args.file_path.clone());
    parser.parse_file(None, true).await?;

    // Parse timestamps if provided
    let start_time = if let Some(start_str) = &args.start_time {
        Some(start_str.parse::<DateTime<Utc>>()
            .map_err(|e| PcapNGError::TimestampError(format!("Invalid start time: {}", e)))?)
    } else {
        None
    };

    let end_time = if let Some(end_str) = &args.end_time {
        Some(end_str.parse::<DateTime<Utc>>()
            .map_err(|e| PcapNGError::TimestampError(format!("Invalid end time: {}", e)))?)
    } else {
        None
    };

    let filtered_packets = PcapNGAnalyzer::filter_packets(
        &parser.packets,
        args.interface_id,
        start_time,
        end_time,
        args.min_size,
        args.max_size,
    );

    let max_results = args.max_results.unwrap_or(1000);
    let result_packets: Vec<_> = filtered_packets.into_iter().take(max_results).collect();

    let result = serde_json::json!({
        "success": true,
        "filter_criteria": {
            "file_path": args.file_path,
            "interface_id": args.interface_id,
            "start_time": args.start_time,
            "end_time": args.end_time,
            "min_size": args.min_size,
            "max_size": args.max_size,
            "max_results": max_results
        },
        "total_matches": result_packets.len(),
        "packets": result_packets
    });

    Ok(ToolResult::new(vec![ToolResultContent::Text {
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| PcapNGError::JsonError(e))?,
    }]))
}

pub async fn handle_get_statistics(args: serde_json::Value) -> Result<ToolResult> {
    let args: GetStatsArgs = serde_json::from_value(args)
        .map_err(|e| PcapNGError::JsonError(e))?;

    info!("Generating statistics for file: {}", args.file_path);

    let mut parser = PcapNGParser::new(args.file_path.clone());
    parser.parse_file(None, false).await?;

    let statistics = PcapNGAnalyzer::generate_statistics(&parser)?;

    let result = serde_json::json!({
        "success": true,
        "statistics": statistics
    });

    Ok(ToolResult::new(vec![ToolResultContent::Text {
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| PcapNGError::JsonError(e))?,
    }]))
}

pub async fn handle_list_interfaces(args: serde_json::Value) -> Result<ToolResult> {
    let args: ListInterfacesArgs = serde_json::from_value(args)
        .map_err(|e| PcapNGError::JsonError(e))?;

    info!("Listing interfaces for file: {}", args.file_path);

    let mut parser = PcapNGParser::new(args.file_path.clone());
    parser.parse_file(Some(1), false).await?; // Only need to parse headers

    let result = serde_json::json!({
        "success": true,
        "file_path": args.file_path,
        "interfaces": parser.interfaces,
        "sections": parser.sections
    });

    Ok(ToolResult::new(vec![ToolResultContent::Text {
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| PcapNGError::JsonError(e))?,
    }]))
}
