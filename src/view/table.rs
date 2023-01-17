use tabled::{builder::Builder, Style};

use super::View;

pub struct TableView {
    print_name: bool,
    buf: Builder<'static>,
}

impl TableView {
    pub fn new(print_name: bool) -> Self {
        Self {
            print_name,
            buf: Builder::new(),
        }
    }
}

impl View for TableView {
    fn render(&mut self, ip: std::net::Ipv4Addr, name: &str, _: crate::config::PacketType) {
        let mut record = vec![ip.to_string()];

        if self.print_name {
            record.push(name.to_string());
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
