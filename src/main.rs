// todo: Add formatting options (csv, table)

use std::{
    net::Ipv4Addr,
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver, Sender},
        Arc,
    },
};

use config::{Config, PacketType};
use pcap::{Active, Capture, Device, Linktype};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    Packet,
};
use trust_dns_proto::{op::MessageType, serialize::binary::BinDecodable};
use view::{csv::CsvView, table::TableView, text::TextView};

mod config;
mod view;

fn main() {
    let config = config::Config::parse();

    let dev = match config.device.clone() {
        Some(device) => Device::from(device.as_str()),
        None => Device::lookup().unwrap().unwrap(),
    };

    let cap = Capture::from_device(dev)
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .open()
        .unwrap();

    let link_type = cap.get_datalink();
    if link_type != Linktype::ETHERNET {
        eprintln!("Unsupported data-link layer protocol");
        exit(-1);
    }

    let ctrlc = Arc::new(AtomicBool::new(false));
    let ctrlc1 = ctrlc.clone();
    ctrlc::set_handler(move || ctrlc1.store(true, Ordering::SeqCst))
        .expect("Error setting Ctrl-C handler");

    let (cx, rx) = channel();

    let _ = std::thread::spawn(move || read_packets(cap, cx, ctrlc));

    print_dns_packets(rx, config)
}

fn read_packets(mut cap: Capture<Active>, cx: Sender<Vec<u8>>, ctrlc: Arc<AtomicBool>) {
    while let Ok(packet) = cap.next_packet() {
        if ctrlc.load(Ordering::SeqCst) {
            break;
        }

        let payload = packet.as_ref().to_vec();
        cx.send(payload).unwrap();
    }
}

fn print_dns_packets(rx: Receiver<Vec<u8>>, config: Config) {
    let filter = config.filter;
    let opt_name = config.options.service_name;

    match config.format {
        config::OutputFormat::Text => recv_packets(rx, TextView::new(opt_name), filter),
        config::OutputFormat::Table => recv_packets(rx, TableView::new(opt_name), filter),
        config::OutputFormat::Csv => recv_packets(rx, CsvView::new(opt_name), filter),
    }
}

fn recv_packets(rx: Receiver<Vec<u8>>, mut printer: impl view::View, filter: Option<PacketType>) {
    while let Ok(packet) = rx.recv() {
        let (ip, name, msg_type) = match parse_packet(&packet) {
            Some(data) => data,
            None => continue,
        };

        let is_ignored = matches!(filter, Some(f) if f == msg_type);
        if is_ignored {
            continue;
        }

        printer.render(ip, &name, msg_type);
    }

    printer.flush();
}

fn parse_packet(payload: &[u8]) -> Option<(Ipv4Addr, String, PacketType)> {
    let eth_packet = EthernetPacket::new(payload)?;
    let payload = eth_packet.payload();

    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ip_packet = Ipv4Packet::new(payload)?;
    let payload = ip_packet.payload();

    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        return None;
    }

    let udp_packet = pnet_packet::udp::UdpPacket::new(&payload)?;
    let payload = udp_packet.payload();

    let mut dns_reader = trust_dns_proto::serialize::binary::BinDecoder::new(payload);
    let dns_header = trust_dns_proto::op::Header::read(&mut dns_reader).ok()?;

    // NOTICE:
    // we do not use dns_header.query_count() to get all querties
    // as it SOMEHOW gives very strange numbers.

    let dns_query = trust_dns_proto::op::Query::read(&mut dns_reader).ok()?;

    let dst = ip_packet.get_destination();
    let query_name = dns_query.name().to_string();
    let msg_type = dns_header.message_type().into();

    Some((dst, query_name, msg_type))
}

impl From<MessageType> for PacketType {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Query => Self::Query,
            MessageType::Response => Self::Response,
        }
    }
}
