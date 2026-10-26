//! Small HTTP/1.x server with bounded storage and one request per connection.

use core::fmt::{self, Write};

use smoltcp::socket::tcp;

pub const PORT: u16 = 80;
pub const SOCKET_BUFFER_SIZE: usize = 4096;
const MAX_HEADERS: usize = 2048;
const REQUEST_TIMEOUT_MS: i64 = 5000;
const STALL_TIMEOUT_MS: i64 = 10_000;

const PAGE: &[u8] = br#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rust kernel</title><style>
body{margin:0;background:#101820;color:#eaf2f8;font:18px/1.6 system-ui,sans-serif}
main{max-width:650px;margin:12vh auto;padding:32px}h1{font-size:3rem;line-height:1.1}
a{color:#72e0bd}.label{color:#72e0bd;letter-spacing:.15em;font-size:.8rem}
code{color:#b9d8ef}footer{margin-top:3rem;color:#a1b4c2;font-size:.9rem}
</style></head><body><main><p class="label">BARE METAL / ONLINE</p>
<h1>Hello from the Rust kernel.</h1>
<p>This page is served directly by a small Rust kernel running in QEMU.</p>
<p>An Intel e1000 NIC connects the kernel to an IPv4 and TCP network, powered by smoltcp.</p>
<p>No operating system underneath. No heap required.</p>
<p><a href="/healthz">Check server health &rarr;</a></p>
<footer>Guest <code>10.0.2.15:80</code> &middot; HTTP/1.1 &middot; Rust</footer>
</main></body></html>
"#;

#[derive(Clone, Copy)]
enum Response {
    Page,
    Health,
    BadRequest,
    NotFound,
    MethodNotAllowed,
    HeaderTooLarge,
}

impl Response {
    fn content(self) -> (&'static str, &'static str, &'static [u8]) {
        let (status, body): (_, &[u8]) = match self {
            Self::Page => return ("200 OK", "text/html; charset=utf-8", PAGE),
            Self::Health => ("200 OK", b"ok\n"),
            Self::BadRequest => ("400 Bad Request", b"Bad request\n"),
            Self::NotFound => ("404 Not Found", b"Not found\n"),
            Self::MethodNotAllowed => ("405 Method Not Allowed", b"Method not allowed\n"),
            Self::HeaderTooLarge => (
                "431 Request Header Fields Too Large",
                b"Request headers too large\n",
            ),
        };
        (status, "text/plain; charset=utf-8", body)
    }
}

#[derive(Clone, Copy)]
enum Phase {
    Reading,
    Sending,
    Closing,
}

pub struct Connection {
    // Reused for response headers once request parsing is complete.
    headers: [u8; MAX_HEADERS],
    used: usize,
    sent: usize,
    body: &'static [u8],
    body_sent: usize,
    phase: Phase,
    started: Option<i64>,
    last_progress: i64,
    last_queue: usize,
}

impl Connection {
    pub const fn new() -> Self {
        Self {
            headers: [0; MAX_HEADERS],
            used: 0,
            sent: 0,
            body: &[],
            body_sent: 0,
            phase: Phase::Reading,
            started: None,
            last_progress: 0,
            last_queue: 0,
        }
    }

    pub fn poll(&mut self, socket: &mut tcp::Socket<'_>, now_millis: i64) {
        if !socket.is_open() {
            // TIME-WAIT has no outstanding response data. smoltcp permits
            // listening here, avoiding a minute-long pause between clients.
            *self = Self::new();
            socket.listen(PORT).expect("valid HTTP listen port");
            return;
        }
        if socket.is_listening() {
            return;
        }
        let started = *self.started.get_or_insert(now_millis);
        if matches!(self.phase, Phase::Reading) {
            // Absolute deadline: a client trickling bytes cannot hold a slot.
            if now_millis.saturating_sub(started) >= REQUEST_TIMEOUT_MS {
                socket.abort();
                return;
            }
            if socket.can_recv() {
                let count = socket
                    .recv_slice(&mut self.headers[self.used..])
                    .expect("HTTP receive data available");
                self.used += count;
            }
            if let Some(end) = self.headers[..self.used]
                .windows(4)
                .position(|part| part == b"\r\n\r\n")
            {
                let response = parse_request(&self.headers[..end + 4]);
                self.respond(response, now_millis);
            } else if self.used == MAX_HEADERS {
                self.respond(Response::HeaderTooLarge, now_millis);
            } else if socket.state() == tcp::State::CloseWait && !socket.can_recv() {
                self.respond(Response::BadRequest, now_millis);
            }
        }
        if matches!(self.phase, Phase::Reading) {
            return;
        }
        if socket.send_queue() < self.last_queue {
            self.last_progress = now_millis;
        }
        if now_millis.saturating_sub(self.last_progress) >= STALL_TIMEOUT_MS {
            socket.abort();
            return;
        }
        if matches!(self.phase, Phase::Sending) && socket.can_send() {
            let bytes = if self.sent < self.used {
                &self.headers[self.sent..self.used]
            } else {
                &self.body[self.body_sent..]
            };
            let count = socket.send_slice(bytes).expect("HTTP socket can send");
            if self.sent < self.used {
                self.sent += count;
            } else {
                self.body_sent += count;
            }
            if count != 0 {
                self.last_progress = now_millis;
            }
            if self.sent == self.used && self.body_sent == self.body.len() {
                // close() queues FIN after all buffered response bytes. Keep
                // polling until acknowledged; do not abort a fresh close.
                socket.close();
                self.phase = Phase::Closing;
            }
        }
        self.last_queue = socket.send_queue();
    }

    fn respond(&mut self, response: Response, now_millis: i64) {
        // Honor HEAD even if a later request field is malformed.
        let head_only = self.headers[..self.used].starts_with(b"HEAD ");
        let (status, content_type, body) = response.content();
        let mut output = HeaderWriter {
            bytes: &mut self.headers,
            used: 0,
        };
        write!(
            output,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .expect("bounded response headers");
        if matches!(response, Response::MethodNotAllowed) {
            output.write_str("Allow: GET, HEAD\r\n").unwrap();
        }
        output.write_str("\r\n").unwrap();
        self.used = output.used;
        self.body = if head_only { &[] } else { body };
        self.phase = Phase::Sending;
        self.last_progress = now_millis;
    }
}

fn parse_request(request: &[u8]) -> Response {
    parse_valid_request(request).unwrap_or(Response::BadRequest)
}

fn parse_valid_request(request: &[u8]) -> Option<Response> {
    let text = core::str::from_utf8(request).ok()?;
    let mut lines = text.strip_suffix("\r\n\r\n")?.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let method = request_line.next()?;
    let target = request_line.next()?;
    let version = request_line.next()?;
    if request_line.next().is_some()
        || !is_token(method)
        || !target.starts_with('/')
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }
    let mut has_host = false;
    let mut has_length = false;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if !is_token(name)
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 127))
        {
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("host") {
            if has_host
                || value.is_empty()
                || value.bytes().any(|byte| byte <= b' ' || byte == b',')
            {
                return None;
            }
            has_host = true;
        } else if name.eq_ignore_ascii_case("content-length") {
            // No request bodies. Reject duplicates and ambiguous framing, even
            // when multiple Content-Length fields all claim an empty body.
            if has_length || value.is_empty() || !value.bytes().all(|byte| byte == b'0') {
                return None;
            }
            has_length = true;
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return None;
        }
    }
    if version == "HTTP/1.1" && !has_host {
        return None;
    }
    if !matches!(method, "GET" | "HEAD") {
        return Some(Response::MethodNotAllowed);
    }
    Some(match target.split('?').next()? {
        "/" => Response::Page,
        "/healthz" => Response::Health,
        _ => Response::NotFound,
    })
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
}

struct HeaderWriter<'a> {
    bytes: &'a mut [u8],
    used: usize,
}

impl Write for HeaderWriter<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.used.checked_add(value.len()).ok_or(fmt::Error)?;
        let output = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        output.copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}
