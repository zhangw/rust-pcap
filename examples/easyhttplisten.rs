use core::fmt;
use libc::timeval;
use pcap::{Capture, Device, Packet};
use std::{collections::HashMap, env, error::Error, net::Ipv4Addr, time::Duration};

#[derive(Debug)]
struct TcpSession {
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    let octets = ip.octets();
    u32::from_be_bytes(octets)
}

#[derive(Debug)]
struct TcpPacket {
    session: TcpSession,
    ack: u32,
    seq: u32,
    t_ack: bool,
    t_syn: bool,
    t_fin: bool,
    t_rst: bool,
    cap_len: u32,
    payload: Vec<u8>,
    message_id: u64,
}

impl TcpPacket {
    fn message_id(&mut self) -> u64 {
        if self.message_id == 0 {
            // self.message_id =
            let mut id =
                (self.session.src_port as u64) << 48 | (self.session.dst_port as u64) << 32;
            let src_ip_val = ipv4_to_u32(self.session.src_ip) as u64;
            let dest_ip_val = ipv4_to_u32(self.session.dst_ip) as u64;
            let ip_val = (src_ip_val + dest_ip_val) & 0xffff_ffff;
            id |= ip_val ^ (self.ack as u64);
            self.message_id = id;
        }
        self.message_id
    }
}

#[derive(Debug)]
struct PacketError {
    message: String,
}

impl PacketError {
    fn new(message: &str) -> PacketError {
        PacketError {
            message: message.to_string(),
        }
    }
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for PacketError {}

fn timeval_to_duration(tv: timeval) -> Duration {
    let seconds = tv.tv_sec as u64;
    let microseconds = tv.tv_usec as u64;
    Duration::new(seconds, (microseconds * 1_000) as u32)
}

fn parse(packet: Packet) -> Result<TcpPacket, PacketError> {
    let pkt_data = packet.data;
    let pkth_ts = timeval_to_duration(packet.header.ts);
    let pkth_caplen = packet.header.caplen;
    let pkth_len = packet.header.len;
    println!(
        "Packet captured at {:?} with caplen {} and len {}",
        pkth_ts, pkth_caplen, pkth_len
    );
    if pkth_len != pkth_caplen {
        return Err(PacketError::new("Truncated packet"));
    } else {
        // ethernet header (14 bytes)
        if pkt_data.len() <= 14 {
            return Err(PacketError::new("Invalid tcp packet"));
        }
        let ldata = &pkt_data[14..];
        if ldata[0] >> 4 == 4 {
            if ldata.len() < 20 {
                return Err(PacketError::new("Invalid IPv4"));
            }
            //ldata[9]
            let ihl = ((ldata[0] & 0x0F) as usize) * 4;
            if ihl < 20 || ihl > 60 {
                return Err(PacketError::new("Invalid IPv4 IHL"));
            }
            if ldata.len() < ihl {
                return Err(PacketError::new("Invalid IPv4 opts"));
            }
            let net_layer = &ldata[..ihl];
            let ndata = &ldata[net_layer.len()..];
            let dof = ((ndata[12] >> 4) as usize) * 4;
            if dof < 20 || ndata.len() < dof {
                return Err(PacketError::new("Invalid TCP header length"));
            }
            if net_layer.len() < 20 {
                return Err(PacketError::new(
                    "Invalid IPv4 header length for IP extraction",
                ));
            }
            let src_ip = Ipv4Addr::new(net_layer[12], net_layer[13], net_layer[14], net_layer[15]);
            let dest_ip = Ipv4Addr::new(net_layer[16], net_layer[17], net_layer[18], net_layer[19]);
            let transfer_layer = &ndata[..dof as usize];
            if transfer_layer.len() < 4 {
                return Err(PacketError::new(
                    "Invalid TCP header length for port extraction",
                ));
            }
            let src_port = u16::from_be_bytes([transfer_layer[0], transfer_layer[1]]);
            let dest_port = u16::from_be_bytes([transfer_layer[2], transfer_layer[3]]);
            //println!("Source IP: {}, Dest IP: {}", src_ip, dest_ip);
            //println!("Source Port: {}, Dest Port: {}", src_port, dest_port);
            let tcp_session = TcpSession {
                src_ip,
                src_port,
                dst_ip: dest_ip,
                dst_port: dest_port,
            };
            let tcp_packet = TcpPacket {
                session: tcp_session,
                ack: u32::from_be_bytes(
                    transfer_layer[4..8]
                        .try_into()
                        .expect("slice with incorrect length"),
                ),
                seq: u32::from_be_bytes(
                    transfer_layer[8..12]
                        .try_into()
                        .expect("slice with incorrect length"),
                ),
                t_fin: transfer_layer[13] & 0x01 != 0,
                t_syn: transfer_layer[13] & 0x02 != 0,
                t_rst: transfer_layer[13] & 0x04 != 0,
                t_ack: transfer_layer[13] & 0x10 != 0,
                cap_len: pkth_caplen,
                payload: ndata[dof as usize..].to_vec(),
                message_id: 0,
            };
            return Ok(tcp_packet);
        } else {
            return Err(PacketError::new("Only IPv4 supported"));
        }
    }
}

fn process_packet(packet: Packet, tcp_streams: &mut HashMap<u64, Vec<Vec<u8>>>) {
    let mut tcp_packet = match parse(packet) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Parse Tcp Error: {}", e);
            return;
        }
    };
    let message_id = tcp_packet.message_id();
    let grp_packets = tcp_streams.entry(message_id).or_insert(vec![]);
    if tcp_packet.payload.len() > 0 {
        grp_packets.push(tcp_packet.payload);
        let tailer = grp_packets.last().unwrap();
        if tailer.ends_with(&[0x0a]) {
            let mut http_data = Vec::new();
            for p in grp_packets.iter() {
                http_data.extend(p);
            }
            let http_str = String::from_utf8(http_data).unwrap();
            println!("HTTP Data: {}", http_str);
            grp_packets.clear();
            tcp_streams.remove(&message_id);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut port = "8000";
    let mut device_ip = "127.0.0.1";
    if args.len() != 3 {
        eprintln!("Usage: {} <port> <device ip>", args[0]);
        eprintln!("Using default port {} and device IP {}", port, device_ip);
        // std::process::exit(1);
    } else {
        port = &args[1];
        device_ip = &args[2];
    }
    let devices = Device::list().unwrap();
    let device = devices
        .into_iter()
        .find(|d| d.addresses.iter().any(|a| a.addr.to_string().eq(device_ip)))
        .expect(&format!(
            "No device found with the given IP address {}",
            device_ip
        ));
    let device_name = device.name;
    println!("Using device {} for IP address {}", device_name, device_ip);
    let filter = format!("tcp port {}", port);
    let mut cap = Capture::from_device(device_name.as_str())
        .expect("Capture create failed")
        .immediate_mode(true)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .expect("Capture open failed");
    cap.filter(&filter, true)
        .expect("Capture bpf filter failed");
    println!(
        "Listening on port {} for TCP traffic on device {}",
        port, device_name
    );
    let mut tcp_streams: HashMap<u64, Vec<Vec<u8>>> = HashMap::new();
    loop {
        match cap.next_packet() {
            Ok(packet) => process_packet(packet, &mut tcp_streams),
            Err(pcap::Error::TimeoutExpired) => {
                println!("Timeout expired, no packets captured. Waiting...");
            }
            Err(e) => {
                eprintln!("Pcap Error: {}", e);
                break;
            }
        };
    }
}
