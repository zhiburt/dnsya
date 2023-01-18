use tabled::{builder::Builder, Style};

use crate::config::PacketType;

use super::{PacketInfo, View};

pub struct TableView {
    _name: bool,
    _type: bool,
    _port: bool,
    buf: Builder<'static>,
}

impl TableView {
    pub fn new(print_name: bool, print_type: bool, print_port: bool) -> Self {
        Self {
            _name: print_name,
            _port: print_port,
            _type: print_type,
            buf: Builder::new(),
        }
    }
}

impl View for TableView {
    fn render(&mut self, pkt: PacketInfo) {
        let mut record = vec![pkt.dst.to_string()];

        if self._port {
            record.push(pkt.dst_port.to_string());
        }

        if self._name {
            record.push(pkt.query_name.to_string());
        }

        if self._type {
            record.push(msg_type_to_string(pkt.msg_type).to_string());
        }

        self.buf.add_record(record);
    }

    fn flush(&mut self) {
        let buf = std::mem::replace(&mut self.buf, Builder::default());
        let mut table = buf.build();
        table.with(Style::modern().off_horizontal().off_horizontals());

        println!("\n{}", table);
    }
}

fn msg_type_to_string(t: PacketType) -> &'static str {
    match t {
        PacketType::Query => "q",
        PacketType::Response => "r",
    }
}
