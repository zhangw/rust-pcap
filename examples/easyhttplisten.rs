use pcap::{Capture, Device};
use std::{env, str};

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
        .open()
        .expect("Capture open failed");
    cap.filter(&filter, true)
        .expect("Capture bpf filter failed");
    println!(
        "Listening on port {} for TCP traffic on device {}",
        port, device_name
    );
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                println!("Packet captured: {:?}", packet);
                let pkt_data = packet.data;
                if pkt_data.len() < 54 {
                    // ethernet header (14 bytes), IP header (20 bytes), TCP header (20 bytes)
                    // not a TCP packet
                    continue;
                }
                let tcp_payload = &pkt_data[54..];
                if let Ok(payload_str) = str::from_utf8(tcp_payload) {
                    println!("{}", payload_str);
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                break;
            }
        }
    }
}
