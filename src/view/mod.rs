use std::net::{IpAddr, Ipv4Addr};

use crate::config::PacketType;

pub mod csv;
pub mod table;
pub mod text;

#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub query_name: String,
    pub msg_type: PacketType,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self::new(
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0,
            IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            0,
            String::new(),
            PacketType::Query,
        )
    }
}

impl PacketInfo {
    pub fn new(
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        query_name: String,
        msg_type: PacketType,
    ) -> Self {
        Self {
            src,
            src_port,
            dst,
            dst_port,
            query_name,
            msg_type,
        }
    }
}

pub trait View {
    fn render(&mut self, pkt: PacketInfo);
    fn flush(&mut self);
}
