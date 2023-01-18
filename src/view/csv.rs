use crate::config::PacketType;

use super::{PacketInfo, View};

pub struct CsvView {
    _name: bool,
    _type: bool,
    _port: bool,
}

impl CsvView {
    pub fn new(_name: bool, _type: bool, _port: bool) -> Self {
        Self {
            _name,
            _type,
            _port,
        }
    }
}

impl View for CsvView {
    fn render(&mut self, pkt: PacketInfo) {
        print!("{}", pkt.dst);

        if self._port {
            print!(",{}", pkt.dst_port);
        }

        if self._name {
            print!(",{}", pkt.query_name);
        }

        if self._type {
            print!(",{}", msg_type_to_string(pkt.msg_type));
        }

        println!()
    }

    fn flush(&mut self) {}
}

fn msg_type_to_string(t: PacketType) -> &'static str {
    match t {
        PacketType::Query => "q",
        PacketType::Response => "r",
    }
}
