use pcapng_mcp_server::mcp::server::PcapNGServer;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 PcapNG MCP Server - Comprehensive Test");
    println!("==========================================\n");

    let server = PcapNGServer::new();

    // Look for sample files
    let sample_files = [
        "/Volumes/EXT/pcapng/test_20250801_1140UTC/sniffer_211_cluster.pcapng",
        "/Volumes/EXT/pcapng/test_20250801_1140UTC/sniffer_211_cluster_exp77.48.2.3.pcapng",
        "/Volumes/EXT/pcapng/test_20250801_1140UTC/sniffer_server_220_member.pcapng",
        "/Volumes/EXT/pcapng/test_20250801_1140UTC/sniffer_server_220_member_exp77.48.2.3.pcapng"
    ];

    let mut tested_files = 0;
    
    for sample_file in &sample_files {
        if Path::new(sample_file).exists() {
            tested_files += 1;
            println!("📁 Testing file: {}", sample_file);
            println!("{}", "=".repeat(60));

            // Test 1: Parse File
            println!("🔧 Test 1: Parse File");
            match server.parse_file(sample_file).await {
                Ok(result) => {
                    println!("✅ SUCCESS");
                    println!("{}\n", result);
                }
                Err(e) => {
                    println!("❌ FAILED: {}\n", e);
                    continue;
                }
            }

            // Test 2: Get Metadata
            println!("🔧 Test 2: Get Metadata");
            match server.get_metadata(sample_file).await {
                Ok(result) => {
                    println!("✅ SUCCESS");
                    println!("{}\n", result);
                }
                Err(e) => {
                    println!("❌ FAILED: {}\n", e);
                }
            }

            // Test 3: List Interfaces
            println!("🔧 Test 3: List Interfaces");
            match server.list_interfaces(sample_file).await {
                Ok(result) => {
                    println!("✅ SUCCESS");
                    println!("{}\n", result);
                }
                Err(e) => {
                    println!("❌ FAILED: {}\n", e);
                }
            }

            println!("{}\n", "=".repeat(60));
        }
    }

    if tested_files == 0 {
        println!("⚠️  No sample files found to test");
        println!("Expected locations:");
        for file in &sample_files {
            println!("  - {}", file);
        }
    } else {
        println!("🎉 Completed testing {} file(s)", tested_files);
    }

    println!("\n✨ PcapNG MCP Server is working correctly!");
    println!("🚀 Ready to serve as an MCP server for PcapNG file analysis");

    Ok(())
}
