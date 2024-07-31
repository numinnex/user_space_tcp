use crate::tcp;
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown},
    sync::{Arc, Condvar, Mutex},
};
use tun_tap::Mode;

const SEND_QUEUE_SIZE: usize = 1024;
//const IP_V4_PROTOCOL: u16 = 0x800;
const TCP_PROTOCOL: u8 = 0x06;

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

#[derive(Default)]
struct Handler {
    coordinator: Mutex<ConnectionCoordinator>,
    pending_var: Condvar,
}

type InterfaceHandle = Arc<Handler>;

pub struct Interface {
    handler: Option<InterfaceHandle>,
    t_handle: Option<std::thread::JoinHandle<io::Result<()>>>,
}

impl Drop for Interface {
    fn drop(&mut self) {
        self.handler
            .as_mut()
            .unwrap()
            .coordinator
            .lock()
            .unwrap()
            .terminate = true;

        drop(self.handler.take());
        self.t_handle
            .take()
            .expect("interface dropped more than once")
            .join()
            .unwrap()
            .unwrap();
    }
}

#[derive(Default)]
struct ConnectionCoordinator {
    terminate: bool,
    connections: HashMap<Quad, tcp::Connection>,
    pending: HashMap<u16, VecDeque<Quad>>,
}

fn packet_loop(mut nic: tun_tap::Iface, handler: InterfaceHandle) -> io::Result<()> {
    let mut buf = [0u8; 1504];

    loop {
        //TODO: set a timeout for TCP timers and termiantion of coordinator
        let n = nic.recv(&mut buf).expect("Failed to recv on nic");
        // If no without_packet_info, those are required.
        // let _flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // if eth_proto != IP_V4_PROTOCOL {
        //     continue;
        // }

        //TODO: if self.terminate && Arc::get_strong_count(&conn_cord) == 1
        // tear down all connections

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
                        let mut conn_cord_guard = handler.coordinator.lock().unwrap();
                        let conn_cord = &mut *conn_cord_guard;
                        let src_port = tcp_header.source_port();
                        let dst_port = tcp_header.destination_port();
                        let quad = Quad {
                            src: (src, src_port),
                            dst: (dst, dst_port),
                        };
                        match conn_cord.connections.entry(quad) {
                            Entry::Occupied(mut c) => {
                                c.get_mut()
                                    .on_packet(&mut nic, ip_header, tcp_header, &buf[data_pos..n])
                                    .expect("Failed to handle packet");
                            }
                            Entry::Vacant(e) => {
                                if let Some(pending) =
                                    conn_cord.pending.get_mut(&tcp_header.destination_port())
                                {
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
                                        pending.push_back(quad);
                                        drop(conn_cord_guard);
                                        handler.pending_var.notify_all();
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ignoring weird tcp packet {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ignoring weird ip packet {:?}", e);
            }
        }
    }
}

impl Default for Interface {
    fn default() -> Self {
        let nic = tun_tap::Iface::without_packet_info("tun0", Mode::Tun)
            .expect("Failed to create tun interface");
        let handler = Arc::new(Handler::default());
        let handle = {
            let handler = handler.clone();
            std::thread::spawn(move || {
                // Do the main accept loop.
                packet_loop(nic, handler)
            })
        };
        Interface {
            handler: Some(handler),
            t_handle: Some(handle),
        }
    }
}

impl Interface {
    pub fn bind(&mut self, port: u16) -> io::Result<TcpListener> {
        let mut conn_cord = self.handler.as_mut().unwrap().coordinator.lock().unwrap();
        // TODO - accept SYN packets on given port.
        match conn_cord.pending.entry(port) {
            Entry::Occupied(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "Port already bound",
                ));
            }
            Entry::Vacant(p) => {
                p.insert(Default::default());
            }
        };
        drop(conn_cord);
        Ok(TcpListener(port, self.handler.as_mut().unwrap().clone()))
    }
}

pub struct TcpStream(Quad, InterfaceHandle);

impl Drop for TcpStream {
    fn drop(&mut self) {
        eprintln!("Dropping TcpStream");
        //TODO: Eventually remove from active connections
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut conn_cord = self.1.coordinator.lock().unwrap();
        let conn = conn_cord.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection not found, despite TcpStream being preset.",
            )
        })?;

        if conn.incomming.is_empty() {
            // TODO: Block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "No data available",
            ));
        }

        //TODO: return FIN if nread == 0
        let mut nread = 0;
        let (head, tail) = conn.incomming.as_slices();
        let hread = std::cmp::min(buf.len(), head.len());
        buf.copy_from_slice(&head[..hread]);
        let tread = std::cmp::min(buf.len() - hread, tail.len());
        buf.copy_from_slice(&tail[..tread]);
        nread += tread;
        drop(conn.incomming.drain(..nread));
        Ok(nread)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut conn_cord = self.1.coordinator.lock().unwrap();
        let conn = conn_cord.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection not found, despite TcpStream being preset.",
            )
        })?;

        if conn.unacked.len() >= SEND_QUEUE_SIZE {
            // TODO: Block
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too many bytes buffered",
            ));
        }

        let nwrite = std::cmp::min(buf.len(), SEND_QUEUE_SIZE - conn.unacked.len());
        conn.unacked.extend(&buf[..nwrite]);

        //TODO: wake up a writer
        Ok(nwrite)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut conn_cord = self.1.coordinator.lock().unwrap();
        let conn = conn_cord.connections.get_mut(&self.0).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "Connection not found, despite TcpStream being preset.",
            )
        })?;

        if conn.unacked.is_empty() {
            Ok(())
        } else {
            // TODO: Block
            Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Too many bytes buffered",
            ))
        }
    }
}

pub struct TcpListener(u16, InterfaceHandle);

impl TcpListener {
    pub fn try_accept(&self) -> std::io::Result<TcpStream> {
        let mut conn_cord = self.1.coordinator.lock().unwrap();
        loop {
            if let Some(quad) = conn_cord
                .pending
                .get_mut(&self.0)
                .expect("Port closed while connection is still alive...")
                .pop_front()
            {
                return Ok(TcpStream(quad, self.1.clone()));
            } else {
                // TODO: Block
                conn_cord = self.1.pending_var.wait(conn_cord).unwrap();
            }
        }
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let pending = self
            .1
            .coordinator
            .lock()
            .unwrap()
            .pending
            .remove(&self.0)
            .expect("");
        for quad in pending {
            //TODO: terminate conn_cord.connections[quad];
            unimplemented!()
        }
    }
}

impl TcpStream {
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        //TODO: terminate connection gracefully with FIN
        Ok(())
    }
}
