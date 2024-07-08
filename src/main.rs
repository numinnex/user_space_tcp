use std::{
    collections::{hash_map::Entry, HashMap},
    net::Ipv4Addr,
};
use tun_tap::Mode;
const IP_V4_PROTOCOL: u16 = 0x800;
const TCP_PROTOCOL: u8 = 0x06;
mod tcp;

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut nic = tun_tap::Iface::without_packet_info("tun0", Mode::Tun)
        .expect("Failed to create tun interface");
    let mut buf = vec![0u8; 1504];
    loop {
        let n = nic.recv(&mut buf).expect("Failed to recv on nic");
        // If no without_packet_info, those are required.
        // let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != IP_V4_PROTOCOL {
        //     continue;
        // }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..n]) {
            Ok(ip_header) => {
                let src = ip_header.source_addr();
                let dst = ip_header.destination_addr();
                let proto = ip_header.protocol().0;
                if proto != TCP_PROTOCOL {
                    continue;
                }

                let ip_header_size = ip_header.slice().len();
                match etherparse::TcpHeaderSlice::from_slice(&buf[ip_header_size..n]) {
                    Ok(tcp_header) => {
                        let tcp_header_size = tcp_header.slice().len();
                        let data_pos = ip_header_size + tcp_header_size;
                        let src_port = tcp_header.source_port();
                        let dst_port = tcp_header.destination_port();
                        match connections.entry(Quad {
                            src: (src, src_port),
                            dst: (dst, dst_port),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&mut nic, ip_header, tcp_header, &buf[data_pos..n])
                                    .expect("Failed to handle packet");
                            }
                            Entry::Vacant(e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    ip_header,
                                    tcp_header,
                                    &buf[data_pos..n],
                                )
                                .expect("Failed to accept connection")
                                {
                                    println!("Accepted a new connection, inserting it to the connections map.");
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(_) => {
                //eprintln!("ignoring weird packet {:?}", e);
            }
        }
    }
}
