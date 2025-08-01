use std::path::Path;
use pcapng_mcp_server::{PcapNGServerHandler, MetadataRequest};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = PcapNGServerHandler::new();
    
    // Test file path
    let test_file = Path::new("test_20250801_1140UTC/sniffer_211_cluster.pcapng");
    
    if test_file.exists() {
        println!("Testing metadata extraction with file: {}", test_file.display());
        
        let request = MetadataRequest {
            file_path: test_file.to_path_buf(),
        };
        
        match server.get_metadata(request).await {
            Ok(result) => {
                println!("Metadata result:");
                println!("{}", result);
            }
            Err(e) => {
                println!("Metadata error: {}", e);
            }
        }
    } else {
        println!("Test file not found: {}", test_file.display());
    }
    
    Ok(())
}
