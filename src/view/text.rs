use super::View;

pub struct TextView {
    print_name: bool,
}

impl TextView {
    pub fn new(print_name: bool) -> Self {
        Self { print_name }
    }
}

impl View for TextView {
    fn render(&mut self, ip: std::net::Ipv4Addr, name: &str, _: crate::config::PacketType) {
        print!("{}", ip);

        if self.print_name {
            print!(" {}", name);
        }

        println!()
    }

    fn flush(&mut self) {}
}
