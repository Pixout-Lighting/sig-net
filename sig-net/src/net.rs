use crate::*;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub struct UdpMulticastSocket {
    socket: UdpSocket,
    port: u16,
}

impl UdpMulticastSocket {
    pub fn bind(port: u16) -> Result<Self> {
        let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
        let socket = UdpSocket::bind(addr).map_err(|_| SigNetError::Network)?;
        socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
        Ok(UdpMulticastSocket { socket, port })
    }

    pub fn set_multicast_ttl(&self, ttl: u8) -> Result<()> {
        self.socket
            .set_multicast_ttl_v4(ttl as u32)
            .map_err(|_| SigNetError::Network)
    }

    pub fn set_multicast_loopback(&self, enabled: bool) -> Result<()> {
        self.socket
            .set_multicast_loop_v4(enabled)
            .map_err(|_| SigNetError::Network)
    }

    pub fn join_multicast_group(&self, multicast_addr: Ipv4Addr, interface: Option<Ipv4Addr>) -> Result<()> {
        let iface = interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.socket
            .join_multicast_v4(&multicast_addr, &iface)
            .map_err(|_| SigNetError::Network)
    }

    pub fn leave_multicast_group(&self, multicast_addr: Ipv4Addr, interface: Option<Ipv4Addr>) -> Result<()> {
        let iface = interface.unwrap_or(Ipv4Addr::UNSPECIFIED);
        self.socket
            .leave_multicast_v4(&multicast_addr, &iface)
            .map_err(|_| SigNetError::Network)
    }

    pub fn send_to(&self, data: &[u8], dest: SocketAddrV4) -> Result<usize> {
        self.socket.send_to(data, dest).map_err(|_| SigNetError::Network)
    }

    pub fn send_multicast(&self, data: &[u8], universe: u16) -> Result<usize> {
        let octets = calculate_multicast_address(universe)?;
        let addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        let dest = SocketAddrV4::new(addr, self.port);
        self.send_to(data, dest)
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddrV4)> {
        self.socket
            .recv_from(buf)
            .map_err(|_| SigNetError::Network)
            .and_then(|(n, addr)| match addr {
                std::net::SocketAddr::V4(v4) => Ok((n, v4)),
                _ => Err(SigNetError::Network),
            })
    }
}
