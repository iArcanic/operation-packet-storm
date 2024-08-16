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
use reqwest::blocking::Client;

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
    let mut http_payloads = Vec::new(); // Store HTTP payloads

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

                                // Extract and store HTTP payloads
                                if tcp_packet.get_source() == 80 || tcp_packet.get_destination() == 80 {
                                    if let Ok(http_payload) = str::from_utf8(tcp_packet.payload()) {
                                        http_payloads.push(http_payload.to_string());
                                    }
                                }
                            }
                        }
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

    // Create plain text data
    let mut output = String::new();
    
    // Summary
    output.push_str("Summary of Packets:\n");
    output.push_str(&format!("TCP Packets: {}\n", tcp_count));
    output.push_str(&format!("UDP Packets: {}\n", udp_count));
    output.push_str(&format!("ICMP Packets: {}\n", icmp_count));
    output.push_str(&format!("Other Packets: {}\n", other_count));

    // Packet Size Histogram
    output.push_str("\nPacket Size Histogram:\n");
    for (size, count) in &packet_size_histogram {
        output.push_str(&format!("Size: {} bytes, Count: {}\n", size, count));
    }

    // TCP Flows
    output.push_str("\nTCP Flows:\n");
    for (flow, (packets, bytes)) in &tcp_flows {
        output.push_str(&format!(
            "{:?} -> {:?}: {} packets, {} bytes\n",
            flow.src_ip, flow.dst_ip, packets, bytes
        ));
    }

    // HTTP Payloads
    output.push_str("\nHTTP Payloads:\n");
    for payload in &http_payloads {
        output.push_str(&format!("{}\n", payload));
    }

    // Send plain text data to the server
    let client = Client::new();
    let res = client.post("http://python-analyser-dashboard:5000/")
        .header("Content-Type", "text/plain")
        .body(output)
        .send()
        .expect("Failed to send data");

    println!("Sent data with status: {:?}", res.status());
}
