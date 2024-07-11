use std::io::{self, Write, Read};
use std::net::{TcpStream, UdpSocket};

fn main() -> io::Result<()> {
    // tcp bytestrings
    let start_conv: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x25\x25";
    let   req_h264: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x28\x28";
    
    // udp bytestrings
    let udp_ctrl: &[u8] = b"\x68\x01\x0d\x80\x80\x80\x80\x20\x08\x00\x80\x01\x00\x00\x00\x00\xa5";
    let cam_down: &[u8] = b"\x68\x01\x0d\x80\x80\x80\x80\x20\x08\x00\x80\x01\x00\x00\x00\x00\xa5";
    let   cam_up: &[u8] = b"\x68\x01\x0d\x80\x80\x80\x80\x20\x08\x00\x80\x01\x00\x00\x00\x00\xa5";


    let mut buffer = [0; 127];

    let mut h264_stream = TcpStream::connect("172.16.10.1:8888")?;
    let mut othr_stream = UdpSocket::bind("172.16.10.1:8888")?;

    h264_stream.write_all(start_conv)?;

    loop {
        h264_stream.write_all(req_h264)?;
        match h264_stream.read(&mut buffer) {
            Ok(0) => {
                eprintln!("fuck");
                break;
            }
            Ok(n) => {
                io::stdout().write_all(&buffer[..n])?;
                io::stdout().flush()?;
                eprintln!("receved {} bytes", n);
            }
            Err(e) => {
                eprintln!("failed to recv data: {}", e);
            }
        }
    }

    Ok(())
}
