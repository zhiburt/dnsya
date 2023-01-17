use std::net::Ipv4Addr;

use crate::config::PacketType;

pub mod csv;
pub mod table;
pub mod text;

pub trait View {
    fn render(&mut self, ip: Ipv4Addr, name: &str, msg_type: PacketType);
    fn flush(&mut self);
}
