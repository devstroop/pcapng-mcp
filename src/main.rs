use pcapng_mcp_server::mcp::server::{PcapNGServer, start_mcp_server};
use tracing_subscriber;
use clap::Parser;

#[derive(Parser)]
#[command(name = "pcapng-mcp-server")]
#[command(about = "A Model Context Protocol server for parsing PcapNG and PCAP files")]
struct Cli {
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Run test mode instead of MCP server
    #[arg(short, long)]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.debug {
        tracing::Level::DEBUG
    } else if cli.verbose {
        tracing::Level::INFO
    } else {
        tracing::Level::WARN
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .init();

    if cli.test {
        // Test mode - run some basic functionality tests
        let server = PcapNGServer::new();
        
        println!("PcapNG MCP Server - Test Mode");
        println!("Server handler created successfully");
        
        // Test with sample file if available
        let test_files = [
            "/Volumes/EXT/pcapng/samples/sample.pcapng",
            "/Volumes/EXT/pcapng/samples/simple.pcapng", 
            "/Volumes/EXT/pcapng/samples/test.pcapng"
        ];
        
        for test_file in &test_files {
            if std::path::Path::new(test_file).exists() {
                println!("\nTesting with file: {}", test_file);
                match server.parse_file(test_file).await {
                    Ok(result) => {
                        println!("✅ Parse successful!");
                        println!("{}", result);
                    }
                    Err(e) => {
                        println!("❌ Parse failed: {}", e);
                    }
                }
                break;
            }
        }
        
        println!("\nUse --help to see available options");
        println!("Remove --test flag to start the MCP server on stdio");
    } else {
        // Start the MCP server
        tracing::info!("Starting PcapNG MCP Server");
        start_mcp_server().await.map_err(|e| format!("Server error: {}", e))?;
    }

    Ok(())
}
