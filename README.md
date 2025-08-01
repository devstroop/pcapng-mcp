# PcapNG MCP Server

A **Model Context Protocol (MCP) server** for parsing and analyzing PcapNG and PCAP network capture files.

## 🎯 Features

✅ **PcapNG & PCAP Support** - Parse both modern PcapNG and classic PCAP files  
✅ **MCP Integration** - Full Model Context Protocol server implementation  
✅ **Metadata Extraction** - File size, packet counts, capture duration, interfaces  
✅ **Interface Analysis** - Network interface details and packet distribution  
✅ **High Performance** - Async Rust implementation with proper error handling  
✅ **JSON Output** - Clean, structured data for easy integration  

## 🚀 Quick Start

### Build & Test
```bash
# Clone and build
cargo build

# Run comprehensive tests with real PcapNG files
cargo run --bin test_server

# Start MCP server
cargo run --bin pcapng-mcp-server

# Test mode (no MCP protocol, just functionality check)
cargo run --bin pcapng-mcp-server -- --test
```

### Example Output
```json
{
  "file_path": "/path/to/capture.pcapng",
  "total_packets": 974,
  "file_size": 211700,
  "file_type": "PcapNG",
  "interfaces": 1,
  "capture_duration": {
    "secs": 19,
    "nanos": 0
  }
}
```

## 🛠️ MCP Tools Available

| Tool | Description |
|------|-------------|
| `parse_pcapng_file` | Parse file and return comprehensive information |
| `get_pcapng_metadata` | Get metadata about file format and structure |
| `list_pcapng_interfaces` | List all network interfaces in the file |
| `filter_pcapng_packets` | Filter packets based on protocol/IP/port criteria |
| `analyze_pcapng_timing` | Analyze packet timing and capture duration |

## 🏗️ Architecture

```
src/
├── main.rs                  # CLI entry point & MCP server startup
├── lib.rs                   # Library exports
├── pcapng/
│   ├── parser.rs           # Core PcapNG/PCAP parsing logic
│   └── types.rs            # Data structures for parsed content
├── mcp/
│   └── server.rs           # MCP server implementation
└── utils/
    └── errors.rs           # Error handling types
```

## 📊 Tested With Real Files

Successfully tested with multiple real-world PcapNG files:
- ✅ 974 packets (19 second capture, 211KB file)
- ✅ 2189 packets (15 second capture, 647KB file, 2 interfaces)
- ✅ 282 packets (8 second capture, 109KB file, 2 interfaces)
- ✅ Various network protocols and interface configurations

## 🔧 Dependencies

- **Rust** - Async/await, error handling, performance
- **rmcp** - Model Context Protocol implementation
- **pcap-parser** - Low-level packet parsing
- **serde** - JSON serialization
- **tokio** - Async runtime

## 🎉 Status: COMPLETE & WORKING

This PcapNG MCP Server is **production-ready** with:
- ✅ Full PcapNG/PCAP parsing capability
- ✅ MCP server architecture implemented  
- ✅ Comprehensive error handling
- ✅ Real-world file validation
- ✅ Clean JSON API responses
- ✅ High-performance async processing

Ready for integration with MCP clients for network packet analysis workflows!
