use std::path::Path;
use pcapng_mcp_server::{PcapNGServerHandler, ParseFileRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = PcapNGServerHandler::new();
    
    // Test multiple files
    let test_files = [
        "test_20250801_1140UTC/sniffer_211_cluster.pcapng",
        "test_20250801_1140UTC/sniffer_server_220_member.pcapng",
    ];
    
    for file_path in &test_files {
        let test_file = Path::new(file_path);
        
        if test_file.exists() {
            println!("\n=== Testing with file: {} ===", test_file.display());
            
            let request = ParseFileRequest {
                file_path: test_file.to_path_buf(),
            };
            
            match server.parse_file(request).await {
                Ok(result) => {
                    println!("{}", result);
                }
                Err(e) => {
                    println!("Parse error: {}", e);
                }
            }
        } else {
            println!("Test file not found: {}", test_file.display());
        }
    }
    
    Ok(())
}
