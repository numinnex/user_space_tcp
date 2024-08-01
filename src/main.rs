use std::io::Read;

mod stream;
mod tcp;

fn main() {
    let mut tcp_interface = stream::Interface::default();
    let listener = tcp_interface
        .bind(5900)
        .expect("Failed to bind to a port 4600 for our user space tcp interface");
    std::thread::spawn(move || {
        while let Ok(mut stream) = listener.try_accept() {
            eprintln!("Accepted a connection");
            let n = stream.read(&mut [0]).unwrap();
            assert_eq!(n, 0);
        }
    })
    .join()
    .unwrap();
}
