use {
    super::*,
    crate::try_ops::{TryGet as _, TryGetMut as _},
    std::{collections::VecDeque, fs::File, os::fd::BorrowedFd},
};

/// A `Read + Write + AsFd` test double. `read()` calls are scripted in advance and return an error
/// if the script runs out, while `write()` calls are recorded (and optionally scripted to fail) so
/// tests can assert on what would have gone out over the wire.
pub struct MockDevice {
    reads: VecDeque<io::Result<Vec<u8>>>,
    writes: Vec<Vec<u8>>,
    write_error: Option<String>,

    /// Backing fd only to satisfy `AsFd`. `poll_readable` is always injected in tests, so this fd
    /// is never actually polled or read from the OS.
    dummy_fd: File,
}

impl MockDevice {
    /// Creates a new `Self` that returns the next item in `reads` in order for each `read()` call.
    pub fn new(reads: impl IntoIterator<Item = io::Result<Vec<u8>>>) -> io::Result<Self> {
        Ok(Self {
            reads: reads.into_iter().collect(),
            writes: Vec::new(),
            write_error: None,
            dummy_fd: File::open("/dev/null")?,
        })
    }

    /// Makes every subsequent `write()` call fail with `io::Error::other(message)`.
    pub fn fail_writes(mut self, message: impl Into<String>) -> Self {
        self.write_error = Some(message.into());
        self
    }

    pub fn writes(&self) -> &[Vec<u8>] { &self.writes }
}

impl Read for MockDevice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let data = self
            .reads
            .pop_front()
            .ok_or_else(|| io::Error::other("Ran out of scripted reads"))??;

        buf.try_get_mut(..data.len())
            .map_err(io::Error::other)?
            .copy_from_slice(&data);

        Ok(data.len())
    }
}

impl Write for MockDevice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(message) = &self.write_error {
            return Err(io::Error::other(message.clone()));
        }

        self.writes.push(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl AsFd for MockDevice {
    fn as_fd(&self) -> BorrowedFd<'_> { self.dummy_fd.as_fd() }
}

/// A scripted sequence of `poll_readable` results, consumed one per call (via interior mutability
/// since `poll_readable` must be `Fn`, not `FnMut`). Returns `Err` if the script runs out.
pub struct MockPoll(RefCell<VecDeque<io::Result<bool>>>);

impl MockPoll {
    pub fn new(items: impl IntoIterator<Item = io::Result<bool>>) -> Self {
        Self(RefCell::new(items.into_iter().collect()))
    }

    pub fn next(&self) -> io::Result<bool> {
        self.0
            .try_borrow_mut()
            .map_err(io::Error::other)?
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::other("Poll script exhausted")))
    }
}

/// Encodes `handler` into a full IPv4 packet so it can be used as a scripted mock to be read.
pub fn encode_mock_packet(handler: &impl Encode) -> Result<Vec<u8>> {
    let mut buf = [0u8; ETHERNET_MTU];
    let proto_len = handler.write_into(&mut buf[Ipv4Header::REPLY_HDR_LEN..])?;
    let ipv4_header = Ipv4Header::try_new(handler.proto(), handler.get_ip_pair(), proto_len)?;
    ipv4_header.write_into(&mut buf);

    Ok(buf.try_get(..ipv4_header.total_len.into())?.to_vec())
}

/// Decodes a full IPv4 packet so tests can assert on structs instead of raw bytes.
pub fn decode_mock_packet(bytes: &[u8]) -> Result<ProtocolHandler<'_>> {
    let (ipv4_header, payload) = Ipv4Header::parse(bytes)?;
    ProtocolHandler::parse(payload, ipv4_header.protocol, ipv4_header.ip_pair)
}
