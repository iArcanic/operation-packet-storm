use pnet::packet::{Packet, ethernet::EthernetPacket};
use pcap::Capture;

fn main() {
    let pcap_file = "data/packet-storm.pcap";

    let mut cap = Capture::from_file(pcap_file).expect("Error opening .pcap file");

    while let Ok(packet) = cap.next_packet() {
        if let Some(eth_packet) = EthernetPacket::new(packet.data) {
            println!("{:?}", eth_packet);
        }
    }
}

