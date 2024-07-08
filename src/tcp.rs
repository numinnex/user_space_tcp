use std::{
    cmp::Ordering,
    io::{self, Write},
};

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

enum State {
    //Closed,
    //Listen,
    SyncRcvd,
    Estab,
    FinWait1,
}

impl State {
    pub fn is_synchronized(&self) -> bool {
        match self {
            State::SyncRcvd => false,
            State::Estab => true,
            State::FinWait1 => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip_header: Ipv4Header,
    tcp_header: TcpHeader,
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
        let wnd = 10;
        let mut connection = Connection {
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
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
        };

        connection.tcp_header.acknowledgment_number = connection.recv.nxt;
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
            .set_payload_len(size)
            .expect("Failed to set ip header payload length.");

        // The kernel does this for us.
        // self.tcp_header.checksum = self.tcp_header
        //     .calc_checksum_ipv4(&self.ip_header, &[])
        //     .expect("Failed to compute checksum for the syn ack response");
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
        self.ip_header.set_payload_len(self.tcp_header.header_len()).expect("Couldn't set ip header payload len.");
        self.write(nic, &[])?;
        Ok(())
    }

    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<(), io::Error> {
        // SND.UNA < SEG.ACK =< SND.NXT
        let ackn = tcp_header.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            /*
            * Deal with this later
            if self.state.is_synchronized() {
                // according to RFC 793 Reset Generation, in this case we should send a RST.
                self.send.nxt = tcp_header.acknowledgment_number();
                self.send_rst(nic)?;
            }
            */
            return Ok(());
        }

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
        if slen == 0 {
            // zero-length segment has seperate set of acceptence rules.
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn + slen - 1, wend)
            {
                return Ok(());
            }
        }

        match self.state {
            State::SyncRcvd => {
                if !tcp_header.ack() {
                    return Ok(());
                }
                self.state = State::Estab;
                // TODO: Needs to be stored in the retransmission queue aswell.
                self.tcp_header.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
                return Ok(());
            }
            State::Estab => {
                if !tcp_header.fin() || !payload.is_empty() {
                    unimplemented!();
                }

                self.write(nic, &[])?;
                Ok(())
            }
            State::FinWait1 => todo!(),
        }
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            if end > start && end > x {
            } else {
                return false;
            }
        }
    }
    true
}
