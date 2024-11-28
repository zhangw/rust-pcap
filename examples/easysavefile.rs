use std::{
    env,
    error::Error,
    fs::File,
    io::{BufWriter, Write},
};

use pcap::{Capture, Device, Packet};

/*
The reference implementation of pcap_setup_dump() in libpcap:

sf_write_header(pcap_t *p, FILE *fp, int linktype, int snaplen)
{
    struct pcap_file_header hdr;

    hdr.magic = p->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;

    /*
     * https://www.tcpdump.org/manpages/pcap-savefile.5.txt states:
     * thiszone (Reserved1): 4-byte not used - SHOULD be filled with 0
     * sigfigs (Reserved2):  4-byte not used - SHOULD be filled with 0
     */
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = snaplen;
    hdr.linktype = linktype;

    if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
        return (-1);

    return (0);
} */
fn write_global_header(
    writer: &mut BufWriter<File>,
    snaplen: i32,
    linktype: i32,
) -> Result<(), Box<dyn Error>> {
    // magic number
    writer.write(&[0xd4, 0xc3, 0xb2, 0xa1])?;
    // version
    writer.write(&[0x02, 0x00, 0x04, 0x00])?;
    // thiszone
    writer.write(&[0x00, 0x00, 0x00, 0x00])?;
    // sigfigs
    writer.write(&[0x00, 0x00, 0x00, 0x00])?;
    // snaplen
    writer.write(&snaplen.to_le_bytes())?;
    // linktype
    writer.write(&linktype.to_le_bytes())?;
    Ok(())
}

/*
The reference implementation of pcap_dump() in libpcap:

void
pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
    register FILE *f;
    struct pcap_sf_pkthdr sf_hdr;

    f = (FILE *)user;
    /*
     * If the output file handle is in an error state, don't write
     * anything.
     *
     * While in principle a file handle can return from an error state
     * to a normal state (for example if a disk that is full has space
     * freed), we have possibly left a broken file already, and won't
     * be able to clean it up. The safest option is to do nothing.
     *
     * Note that if we could guarantee that fwrite() was atomic we
     * might be able to insure that we don't produce a corrupted file,
     * but the standard defines fwrite() as a series of fputc() calls,
     * so we really have no insurance that things are not fubared.
     *
     * http://pubs.opengroup.org/onlinepubs/009695399/functions/fwrite.html
     */
    if (ferror(f))
        return;
    /*
     * Better not try writing pcap files after
     * 2106-02-07 06:28:15 UTC; switch to pcapng.
     * (And better not try writing pcap files with time stamps
     * that predate 1970-01-01 00:00:00 UTC; that's not supported.
     * You could try using pcapng with the if_tsoffset field in
     * the IDB for the interface(s) with packets with those time
     * stamps, but you may also have to get a link-layer type for
     * IBM Bisync or whatever link layer even older forms
     * of computer communication used.)
     */
    sf_hdr.ts.tv_sec  = (bpf_u_int32)h->ts.tv_sec;
    sf_hdr.ts.tv_usec = (bpf_u_int32)h->ts.tv_usec;
    sf_hdr.caplen     = h->caplen;
    sf_hdr.len        = h->len;
    /*
     * We only write the packet if we can write the header properly.
     *
     * This doesn't prevent us from having corrupted output, and if we
     * for some reason don't get a complete write we don't have any
     * way to set ferror() to prevent future writes from being
     * attempted, but it is better than nothing.
     */
    if (fwrite(&sf_hdr, sizeof(sf_hdr), 1, f) == 1) {
        (void)fwrite(sp, h->caplen, 1, f);
    }
}
 */
fn write_packet(writer: &mut BufWriter<File>, packet: &Packet) -> Result<(), Box<dyn Error>> {
    let mut sf_hdr = [0u8; 16];
    sf_hdr[0..4].copy_from_slice(&(packet.header.ts.tv_sec as u32).to_le_bytes());
    sf_hdr[4..8].copy_from_slice(&(packet.header.ts.tv_usec as u32).to_le_bytes());
    sf_hdr[8..12].copy_from_slice(&packet.header.caplen.to_le_bytes());
    sf_hdr[12..16].copy_from_slice(&packet.header.len.to_le_bytes());
    writer.write(&sf_hdr)?;
    writer.write(&packet.data)?;
    Ok(())
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
    let snaplen = 65535;
    let mut cap = Capture::from_device(device_name.as_str())
        .expect("Capture create failed")
        .immediate_mode(true)
        .snaplen(snaplen)
        .timeout(1000)
        .open()
        .expect("Capture open failed");
    cap.filter(&filter, true)
        .expect("Capture bpf filter failed");
    println!(
        "Listening on port {} for TCP traffic on device {}",
        port, device_name
    );
    let linktype = cap.get_datalink();

    let filename = "test_pcap.bin";
    loop {
        match cap.next_packet() {
            Ok(packet) => {
                if packet.data.len() > 54 && packet.data.ends_with(&vec![0x0d, 0x0a]) {
                    // save a packet that has a payload
                    let file = File::create(filename).expect("Failed to create file");
                    let mut writer = BufWriter::new(file);
                    write_global_header(&mut writer, snaplen, linktype.0)
                        .expect("Failed to write global header");
                    write_packet(&mut writer, &packet).expect("Failed to write packet");
                    break;
                }
            }
            Err(e) => {
                eprintln!("Pcap Error: {}", e);
                return;
            }
        }
    }

    let mut cap = Capture::from_file(filename).expect("open file failed");
    let packet = cap.next_packet().expect("fetch packet failed");
    let printable = String::from_utf8_lossy(&packet.data);
    println!("Packet data: {:?}", printable);
}
