use std::{
    collections::VecDeque,
    io::{self, Write},
};

use bitflags::bitflags;
use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

#[derive(Debug)]
enum State {
    //Closed,
    //Listen,
    SyncRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

bitflags! {
    pub struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

impl State {
    pub fn is_synchronized(&self) -> bool {
        match self {
            State::SyncRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip_header: Ipv4Header,
    tcp_header: TcpHeader,

    pub(crate) incomming: VecDeque<u8>,
    pub(crate) unacked: VecDeque<u8>,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    pub fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incomming.is_empty() {
            a |= Available::READ;
        }
        // TODO: Set available WRITE
        a
    }
}

struct SendSequenceSpace {
    // send unacknowledged
    una: u32,
    // send next
    nxt: u32,
    // send window
    wnd: u16,
    // send urgent pointer
    up: bool,
    // segment sequence number used for last window update
    wl1: usize,
    // segment acknowledgment number used for last window update
    wl2: usize,
    // intial send sequence number
    iss: u32,
}

struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept(
        nic: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<Option<Self>, io::Error> {
        if !tcp_header.syn() {
            // only expected SYN packet.
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut connection = Connection {
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd,

                // Not sure what those should be.
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcp_header.sequence_number(),
                nxt: tcp_header.sequence_number() + 1,
                wnd: tcp_header.window_size(),

                // Not sure about that one.
                up: false,
            },
            ip_header: Ipv4Header::new(
                0,
                64,
                IpNumber::TCP,
                ip_header.destination(),
                ip_header.source(),
            )
            .expect("Failed to construct syn ack ip header"),
            tcp_header: TcpHeader::new(
                tcp_header.destination_port(),
                tcp_header.source_port(),
                iss,
                wnd,
            ),
            incomming: Default::default(),
            unacked: Default::default()
        };

        //connection.tcp_header.acknowledgment_number = connection.recv.nxt;
        connection.tcp_header.syn = true;
        connection.tcp_header.ack = true;
        connection.write(nic, &[])?;
        Ok(Some(connection))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> Result<usize, io::Error> {
        let mut buf = [0u8; 1500];
        self.tcp_header.sequence_number = self.send.nxt;
        self.tcp_header.acknowledgment_number = self.recv.nxt;
        let size = std::cmp::min(
            buf.len(),
            self.tcp_header.header_len() + self.ip_header.header_len() + payload.len(),
        );
        self.ip_header
            .set_payload_len(size - self.ip_header.header_len())
            .expect("Failed to set ip header payload length.");
        self.tcp_header.checksum = self
            .tcp_header
            .calc_checksum_ipv4(&self.ip_header, &[])
            .expect("Failed to compute checksum for the syn ack response");

        let mut unwritten = &mut buf[..];
        self.ip_header
            .write(&mut unwritten)
            .expect("Failed to write ip header for syn ack");
        self.tcp_header
            .write(&mut unwritten)
            .expect("Failed to write syn ack");
        let payload_n = unwritten.write(payload)? as u32;
        let unwritten = unwritten.len();
        self.send.nxt = self.send.nxt.wrapping_add(payload_n);

        if self.tcp_header.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp_header.syn = false;
        }
        if self.tcp_header.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp_header.fin = false;
        }
        let n = nic.send(&buf[..buf.len() - unwritten])?;
        Ok(n)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> Result<(), io::Error> {
        //TODO: Fix sequence numbers
        self.tcp_header.rst = true;
        self.tcp_header.sequence_number = 0;
        self.tcp_header.acknowledgment_number = 0;
        self.ip_header
            .set_payload_len(self.tcp_header.header_len())
            .expect("Couldn't set ip header payload len.");
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<Available, io::Error> {
        // !!!!!
        // Not recv their FIN ACK with ack = 2.
        // !!!!!

        // RCV.NXT <= SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT <= SEG.SEQ+SEG.LEN+1 < RCV.NXT.RCV.WND
        let seqn = tcp_header.sequence_number();
        let mut slen = payload.len() as u32;
        if tcp_header.fin() {
            slen += 1
        };
        if tcp_header.syn() {
            slen += 1
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        let okay = if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                false
            } else {
                true
            }
        } else {
            if self.recv.wnd == 0 {
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                false
            } else {
                true
            }
        };
        if !okay {
            self.write(nic, &[])?;
            return Ok(self.availability());
        }
        self.recv.nxt = seqn.wrapping_add(slen);

        if !tcp_header.ack() {
            if tcp_header.syn() {
                self.recv.nxt = seqn.wrapping_add(1)
            }
            return Ok(self.availability());
        }

        let ackn = tcp_header.acknowledgment_number();
        if let State::SyncRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                self.state = State::Estab;
            } else {
                // TODO: RST
            }
        }
        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            println!("got here");
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );

                self.send.una = ackn; 
            }
            assert!(payload.is_empty());

            // Terminate the connection
            if let State::Estab = self.state {
                self.tcp_header.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
                // Our FIN has been ACKed.
                println!("THEY ACKED OUR FIN");
                self.state = State::FinWait2;
            }
        }

        if tcp_header.fin() {
            match self.state {
                State::FinWait2 => {
                    println!("THEY HAVE CLOSED");
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }
        Ok(self.availability())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     ensure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
