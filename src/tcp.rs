use std::io;

use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};

enum State {
    //Closed,
    //Listen,
    SyncRcvd,
    Estab,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
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
        let mut buf = [0u8; 1500];
        if !tcp_header.syn() {
            // only expected SYN packet.
            return Ok(None);
        }

        let iss = 0;
        let connection = Connection {
            state: State::SyncRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,

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
        };

        let mut syn_ack = TcpHeader::new(
            tcp_header.destination_port(),
            tcp_header.source_port(),
            connection.send.iss,
            connection.send.wnd,
        );
        syn_ack.acknowledgment_number = connection.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;
        let ip = Ipv4Header::new(
            syn_ack.header_len_u16(),
            64,
            IpNumber::TCP,
            ip_header.destination(),
            ip_header.source(),
        )
        .expect("Failed to construct syn ack ip header");

        // The kernel does this for us.
        // syn_ack.checksum = syn_ack
        //     .calc_checksum_ipv4(&ip, &[])
        //     .expect("Failed to compute checksum for the syn ack response");

        let unwritten = {
            let mut unwritten = &mut buf[..];
            ip.write(&mut unwritten)
                .expect("Failed to write ip header for syn ack");
            syn_ack
                .write(&mut unwritten)
                .expect("Failed to write syn ack");
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(Some(connection))
    }

    pub fn on_packet(
        &mut self,
        nic: &mut tun_tap::Iface,
        ip_header: Ipv4HeaderSlice,
        tcp_header: TcpHeaderSlice,
        payload: &[u8],
    ) -> Result<(), io::Error> {
        match self.state {
            State::SyncRcvd => {
                Ok(())
            },
            State::Estab => {
                unimplemented!()
            }
        }
    }
}
