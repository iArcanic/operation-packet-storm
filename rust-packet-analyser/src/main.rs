extern crate pcap;
extern crate pnet;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pcap::Capture;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str;

#[derive(Debug, Hash, Eq, PartialEq)]
struct Flow {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

fn main() {
    // Path to the .pcap file
    let pcap_file = "data/packet-storm.pcap";

    // Open the .pcap file
    let mut cap = Capture::from_file(pcap_file).expect("Error opening .pcap file");

    let mut tcp_count = 0;
    let mut udp_count = 0;
    let mut icmp_count = 0;
    let mut other_count = 0;
    let mut packet_size_histogram = HashMap::new();
    let mut tcp_flows: HashMap<Flow, (usize, usize)> = HashMap::new(); // (packets, bytes)

    // Iterate through all the packets in the file
    while let Ok(packet) = cap.next_packet() {
        let ethernet = EthernetPacket::new(packet.data).unwrap();
        let packet_size = packet.data.len();

        *packet_size_histogram.entry(packet_size).or_insert(0) += 1;

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            tcp_count += 1;
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                                // Track TCP flows
                                let flow = Flow {
                                    src_ip: ipv4_packet.get_source(),
                                    dst_ip: ipv4_packet.get_destination(),
                                    src_port: tcp_packet.get_source(),
                                    dst_port: tcp_packet.get_destination(),
                                };

                                let entry = tcp_flows.entry(flow).or_insert((0, 0));
                                entry.0 += 1;
                                entry.1 += packet.data.len();

                                // Extract and print HTTP payloads
                                if tcp_packet.get_source() == 80 || tcp_packet.get_destination() == 80 {
                                    if let Ok(http_payload) = str::from_utf8(tcp_packet.payload()) {
                                        println!("HTTP Packet:\n{}", http_payload);
                                    }
                                }
                            }
                        },
                        IpNextHeaderProtocols::Udp => udp_count += 1,
                        IpNextHeaderProtocols::Icmp => icmp_count += 1,
                        _ => other_count += 1,
                    }
                }
            }
            _ => other_count += 1,
        }
    }

    println!("Summary of Packets:");
    println!("TCP Packets: {}", tcp_count);
    println!("UDP Packets: {}", udp_count);
    println!("ICMP Packets: {}", icmp_count);
    println!("Other Packets: {}", other_count);

    // Collect and sort the histogram entries
    let mut histogram_entries: Vec<(&usize, &usize)> = packet_size_histogram.iter().collect();
    histogram_entries.sort_by(|a, b| a.0.cmp(b.0));

    println!("\nPacket Size Histogram:");
    for (size, count) in histogram_entries {
        println!("Size: {} bytes, Count: {}", size, count);
    }

    println!("\nTCP Flows:");
    for (flow, (packet_count, byte_count)) in tcp_flows {
        println!(
            "{:?} -> {:?}: {} packets, {} bytes",
            flow.src_ip, flow.dst_ip, packet_count, byte_count
        );
    }
}

