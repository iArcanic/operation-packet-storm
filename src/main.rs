extern crate pcap;
extern crate pnet;

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pcap::Capture;

fn main() {
    // Path to the .pcap file
    let pcap_file = "data/packet-storm.pcap";

    // Open the .pcap file
    let mut cap = Capture::from_file(pcap_file).expect("Error opening .pcap file");

    let mut tcp_count = 0;
    let mut udp_count = 0;
    let mut icmp_count = 0;
    let mut other_count = 0;

    // Iterate through all the packets in the file
    while let Ok(packet) = cap.next_packet() {
        let ethernet = EthernetPacket::new(packet.data).unwrap();

        match ethernet.get_ethertype() {
            EtherTypes::Ipv4 => {
                let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => tcp_count += 1,
                    IpNextHeaderProtocols::Udp => udp_count += 1,
                    IpNextHeaderProtocols::Icmp => icmp_count += 1,
                    _ => other_count += 1,
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
}

