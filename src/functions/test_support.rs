//! A canned operator for tests: one scripted HTTP response per
//! connection, in order, recording each request so a test can assert what
//! was sent. No mock-server dependency.

/// One canned HTTP response per connection, recording each request so
/// a test can assert what was sent. Same shape as the device client's
/// test server: no mock-server dependency.
pub(crate) async fn canned_operator(
    responses: Vec<String>,
) -> (String, tokio::task::JoinHandle<Vec<String>>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let mut seen = Vec::new();
        for response in responses {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 16384];
            // Read the head, then as much body as Content-Length says.
            loop {
                let n = sock.read(&mut chunk).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            seen.push(String::from_utf8_lossy(&buf).into_owned());
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.shutdown().await.unwrap();
        }
        seen
    });
    (base, handle)
}

pub(crate) fn response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}
