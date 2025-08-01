use crate::pcapng::types::*;
use crate::pcapng::parser::PcapNGParser;
use crate::utils::errors::*;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

pub struct PcapNGAnalyzer;

impl PcapNGAnalyzer {
    pub fn generate_statistics(parser: &PcapNGParser) -> Result<FileStatistics> {
        let file_size = std::fs::metadata(&parser.file_path)
            .map_err(|e| PcapNGError::IoError(e))?
            .len();

        let time_range = Self::calculate_time_range(&parser.packets);
        let interface_stats = Self::calculate_interface_stats(&parser.packets, &parser.interfaces);
        let packet_size_distribution = Self::calculate_size_distribution(&parser.packets);

        Ok(FileStatistics {
            file_path: parser.file_path.clone(),
            file_size,
            total_packets: parser.packets.len(),
            total_sections: parser.sections.len(),
            total_interfaces: parser.interfaces.len(),
            time_range,
            interface_stats,
            packet_size_distribution,
        })
    }

    pub fn filter_packets(
        packets: &[PacketSummary],
        interface_id: Option<u32>,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        min_size: Option<u32>,
        max_size: Option<u32>,
    ) -> Vec<PacketSummary> {
        packets
            .iter()
            .filter(|packet| {
                // Filter by interface ID
                if let Some(iface_id) = interface_id {
                    if packet.interface_id != iface_id {
                        return false;
                    }
                }

                // Filter by start time
                if let Some(start) = start_time {
                    if packet.timestamp < start {
                        return false;
                    }
                }

                // Filter by end time
                if let Some(end) = end_time {
                    if packet.timestamp > end {
                        return false;
                    }
                }

                // Filter by minimum size
                if let Some(min) = min_size {
                    if packet.captured_length < min {
                        return false;
                    }
                }

                // Filter by maximum size
                if let Some(max) = max_size {
                    if packet.captured_length > max {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect()
    }

    fn calculate_time_range(packets: &[PacketSummary]) -> Option<TimeRange> {
        if packets.is_empty() {
            return None;
        }

        let mut min_time = packets[0].timestamp;
        let mut max_time = packets[0].timestamp;

        for packet in packets.iter().skip(1) {
            if packet.timestamp < min_time {
                min_time = packet.timestamp;
            }
            if packet.timestamp > max_time {
                max_time = packet.timestamp;
            }
        }

        let duration = max_time.signed_duration_since(min_time);
        let duration_seconds = duration.num_milliseconds() as f64 / 1000.0;

        Some(TimeRange {
            start: min_time,
            end: max_time,
            duration_seconds,
        })
    }

    fn calculate_interface_stats(
        packets: &[PacketSummary],
        interfaces: &[InterfaceInfo],
    ) -> Vec<InterfaceStats> {
        let mut stats_map: HashMap<u32, (usize, u64, u16)> = HashMap::new();

        for packet in packets {
            let entry = stats_map.entry(packet.interface_id).or_insert((0, 0, 0));
            entry.0 += 1; // packet count
            entry.1 += packet.captured_length as u64; // total bytes
            
            // Get link type from interface info
            if let Some(interface) = interfaces.iter().find(|i| i.id == packet.interface_id) {
                entry.2 = interface.link_type;
            }
        }

        stats_map
            .into_iter()
            .map(|(interface_id, (packet_count, total_bytes, link_type))| {
                let avg_packet_size = if packet_count > 0 {
                    total_bytes as f64 / packet_count as f64
                } else {
                    0.0
                };

                InterfaceStats {
                    interface_id,
                    packet_count,
                    total_bytes,
                    avg_packet_size,
                    link_type,
                }
            })
            .collect()
    }

    fn calculate_size_distribution(packets: &[PacketSummary]) -> PacketSizeDistribution {
        if packets.is_empty() {
            return PacketSizeDistribution {
                min_size: 0,
                max_size: 0,
                avg_size: 0.0,
                size_buckets: vec![],
            };
        }

        let mut sizes: Vec<u32> = packets.iter().map(|p| p.captured_length).collect();
        sizes.sort_unstable();

        let min_size = sizes[0];
        let max_size = sizes[sizes.len() - 1];
        let total_size: u64 = sizes.iter().map(|&s| s as u64).sum();
        let avg_size = total_size as f64 / sizes.len() as f64;

        // Create size buckets
        let buckets = vec![
            (0, 64, "0-64 bytes"),
            (65, 128, "65-128 bytes"),
            (129, 256, "129-256 bytes"),
            (257, 512, "257-512 bytes"),
            (513, 1024, "513-1024 bytes"),
            (1025, 1518, "1025-1518 bytes"),
            (1519, 9000, "1519-9000 bytes"),
            (9001, u32::MAX, "9001+ bytes"),
        ];

        let total_packets = packets.len();
        let size_buckets: Vec<SizeBucket> = buckets
            .into_iter()
            .map(|(min, max, label)| {
                let count = sizes
                    .iter()
                    .filter(|&&size| size >= min && size <= max)
                    .count();
                
                let percentage = if total_packets > 0 {
                    (count as f64 / total_packets as f64) * 100.0
                } else {
                    0.0
                };

                SizeBucket {
                    range: label.to_string(),
                    count,
                    percentage,
                }
            })
            .filter(|bucket| bucket.count > 0)
            .collect();

        PacketSizeDistribution {
            min_size,
            max_size,
            avg_size,
            size_buckets,
        }
    }
}
