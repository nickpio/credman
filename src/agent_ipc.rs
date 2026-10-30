//! Framing only. The trusted launcher supplies the binding; JSON never authenticates it.

use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

pub const MAX_FRAME_BYTES: usize = 65_536;
pub const MAX_NESTING: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    InvalidConfiguration,
    InvalidFrame,
    Io,
    Timeout,
    Poisoned,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfiguration => "invalid channel configuration",
            Self::InvalidFrame => "invalid channel frame",
            Self::Io => "channel I/O failed",
            Self::Timeout => "channel deadline exceeded",
            Self::Poisoned => "channel closed",
        })
    }
}

impl std::error::Error for ChannelError {}

pub struct FramedChannel<Binding> {
    stream: UnixStream,
    binding: Binding,
    read_timeout: Duration,
    write_timeout: Duration,
    poisoned: bool,
}

impl<Binding> fmt::Debug for FramedChannel<Binding> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedChannel")
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl<Binding> FramedChannel<Binding> {
    pub fn new(
        stream: UnixStream,
        binding: Binding,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Result<Self, ChannelError> {
        if read_timeout.is_zero()
            || write_timeout.is_zero()
            || Instant::now().checked_add(read_timeout).is_none()
            || Instant::now().checked_add(write_timeout).is_none()
        {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(ChannelError::InvalidConfiguration);
        }
        // The caller transfers exclusive transport ownership, including any clones.
        if stream.set_nonblocking(false).is_err() {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(ChannelError::Io);
        }
        Ok(Self { stream, binding, read_timeout, write_timeout, poisoned: false })
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn fail<T>(&mut self, error: ChannelError) -> Result<T, ChannelError> {
        self.poisoned = true;
        let _ = self.stream.shutdown(Shutdown::Both);
        Err(error)
    }

    pub fn receive(&mut self) -> Result<Value, ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        let result = (|| {
            let deadline = Instant::now().checked_add(self.read_timeout)
                .ok_or(ChannelError::InvalidConfiguration)?;
            let mut header = [0; 4];
            read_until(&mut self.stream, &mut header, deadline)?;
            let size = u32::from_be_bytes(header) as usize;
            if !(1..=MAX_FRAME_BYTES).contains(&size) {
                return Err(ChannelError::InvalidFrame);
            }
            let mut bytes = vec![0; size];
            read_until(&mut self.stream, &mut bytes, deadline)?;
            strict_json(&bytes)
        })();
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(error),
        }
    }

    pub fn send(&mut self, value: &Value) -> Result<(), ChannelError> {
        if self.poisoned {
            return Err(ChannelError::Poisoned);
        }
        let result = (|| {
            // Validate depth before serialization, which itself recursively walks Value.
            validate_depth(value, 0)?;
            let mut buffer = FrameBuffer(Vec::new());
            serde_json::to_writer(&mut buffer, value).map_err(|_| ChannelError::InvalidFrame)?;
            let bytes = buffer.0;
            if bytes.is_empty() {
                return Err(ChannelError::InvalidFrame);
            }
            let deadline = Instant::now().checked_add(self.write_timeout)
                .ok_or(ChannelError::InvalidConfiguration)?;
            write_until(&mut self.stream, &(bytes.len() as u32).to_be_bytes(), deadline)?;
            write_until(&mut self.stream, &bytes, deadline)
        })();
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(error),
        }
    }
}

impl<Binding> Drop for FramedChannel<Binding> {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

struct FrameBuffer(Vec<u8>);

/// Preflight locally generated output without allocating or touching a live channel.
pub(crate) fn fits_frame(value: &Value) -> bool {
    struct Size(usize);
    impl Write for Size {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_FRAME_BYTES - self.0 {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame limit"));
            }
            self.0 += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    validate_depth(value, 0).is_ok() && serde_json::to_writer(&mut Size(0), value).is_ok()
}

impl Write for FrameBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES - self.0.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

fn remaining(deadline: Instant) -> Result<Duration, ChannelError> {
    deadline.checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero()).ok_or(ChannelError::Timeout)
}

fn io_error(error: std::io::Error) -> ChannelError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ChannelError::Timeout,
        _ => ChannelError::Io,
    }
}

fn read_until(stream: &mut UnixStream, mut bytes: &mut [u8], deadline: Instant) -> Result<(), ChannelError> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?)).map_err(io_error)?;
        match stream.read(bytes) {
            Ok(0) => return Err(ChannelError::Io),
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

fn write_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> Result<(), ChannelError> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?)).map_err(io_error)?;
        match stream.write(bytes) {
            Ok(0) => return Err(ChannelError::Io),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

fn validate_depth(value: &Value, depth: usize) -> Result<(), ChannelError> {
    match value {
        Value::Array(values) => {
            if depth >= MAX_NESTING { return Err(ChannelError::InvalidFrame); }
            for child in values { validate_depth(child, depth + 1)?; }
        }
        Value::Object(values) => {
            if depth >= MAX_NESTING { return Err(ChannelError::InvalidFrame); }
            for child in values.values() { validate_depth(child, depth + 1)?; }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value, ChannelError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = JsonSeed(0).deserialize(&mut decoder).map_err(|_| ChannelError::InvalidFrame)?;
    decoder.end().map_err(|_| ChannelError::InvalidFrame)?;
    Ok(value)
}

struct JsonSeed(usize);

impl<'de> DeserializeSeed<'de> for JsonSeed {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for JsonSeed {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("bounded JSON") }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> { Ok(Value::Bool(value)) }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> { Ok(Value::Number(value.into())) }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> { Ok(Value::Number(value.into())) }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> { Ok(Value::String(value.into())) }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> { Ok(Value::String(value)) }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> { Ok(Value::Null) }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_NESTING { return Err(de::Error::custom("nesting limit")); }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(JsonSeed(self.0 + 1))? { values.push(value); }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.0 >= MAX_NESTING { return Err(de::Error::custom("nesting limit")); }
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) { return Err(de::Error::custom("duplicate key")); }
            let value = map.next_value_seed(JsonSeed(self.0 + 1))?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn channel() -> (FramedChannel<&'static str>, UnixStream) {
        let (local, peer) = UnixStream::pair().unwrap();
        (FramedChannel::new(local, "trusted-binding", Duration::from_millis(100), Duration::from_millis(100)).unwrap(), peer)
    }

    fn raw(peer: &mut UnixStream, bytes: &[u8]) {
        peer.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
        peer.write_all(bytes).unwrap();
    }

    #[test]
    fn pair_roundtrip_multiple_frames_and_safe_debug() {
        let (left, right) = UnixStream::pair().unwrap();
        let mut a = FramedChannel::new(left, "binding-secret", Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        let mut b = FramedChannel::new(right, (), Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        for value in [json!({"credential": "synthetic-marker"}), json!([null, true, 1, -2, 1.25]), json!("ok")] {
            a.send(&value).unwrap();
            assert_eq!(b.receive().unwrap(), value);
        }
        let debug = format!("{a:?}");
        assert!(!debug.contains("binding-secret"));
        assert!(!debug.contains("synthetic-marker"));
    }


    #[test]
    fn invalid_json_poisoned_recursively() {
        let mut bad = vec![
            br#"{"a":1,"a":2}"#.to_vec(),
            br#"{"nested":[{"a":1,"\u0061":2}]}"#.to_vec(),
            br#"{"a":{"x":0,"x":1}}"#.to_vec(),
            b"{} false".to_vec(), b"{]".to_vec(), b"\"\xff\"".to_vec(),
            br#"{"x":"\ud800"}"#.to_vec(), b" ".to_vec(),
        ];
        bad.push(format!("{}0{}", "[".repeat(MAX_NESTING + 1), "]".repeat(MAX_NESTING + 1)).into_bytes());
        for bytes in bad {
            let (mut receiver, mut peer) = channel();
            raw(&mut peer, &bytes);
            assert_eq!(receiver.receive(), Err(ChannelError::InvalidFrame));
            assert!(receiver.is_poisoned());
            assert_eq!(*receiver.binding(), "trusted-binding");
            assert_eq!(receiver.receive(), Err(ChannelError::Poisoned));
            assert_eq!(receiver.send(&json!(null)), Err(ChannelError::Poisoned));
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
        }
    }

    #[test]
    fn length_limits_and_empty_frame() {
        for length in [0u32, MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
            let (mut receiver, mut peer) = channel();
            peer.write_all(&length.to_be_bytes()).unwrap();
            assert_eq!(receiver.receive(), Err(ChannelError::InvalidFrame));
            assert_eq!(receiver.receive(), Err(ChannelError::Poisoned));
        }
        let (mut receiver, mut peer) = channel();
        raw(&mut peer, b"0");
        assert_eq!(receiver.receive().unwrap(), json!(0));
    }

    #[test]
    fn local_preflight_matches_inclusive_encoded_size_and_escape_expansion() {
        let controls = (MAX_FRAME_BYTES - 2) / 6;
        let padding = MAX_FRAME_BYTES - 2 - controls * 6;
        let text = "\u{1}".repeat(controls) + &"a".repeat(padding);
        let exact = json!(text);
        assert_eq!(serde_json::to_vec(&exact).unwrap().len(), MAX_FRAME_BYTES);
        assert!(fits_frame(&exact));
        let over = json!(exact.as_str().unwrap().to_owned() + "a");
        assert_eq!(serde_json::to_vec(&over).unwrap().len(), MAX_FRAME_BYTES + 1);
        assert!(!fits_frame(&over));
        let (mut sender, peer) = channel();
        let mut receiver = FramedChannel::new(peer, (), Duration::from_secs(1), Duration::from_secs(1)).unwrap();
        assert!(!fits_frame(&over));
        assert!(!sender.is_poisoned());
        sender.send(&json!(null)).unwrap();
        assert_eq!(receiver.receive().unwrap(), json!(null));
    }

    #[test]
    fn local_preflight_rejects_excess_nesting() {
        let mut value = json!(0);
        for _ in 0..MAX_NESTING { value = Value::Array(vec![value]); }
        assert!(fits_frame(&value));
        assert!(!fits_frame(&Value::Array(vec![value])));
    }

    #[test]
    fn exact_maximum_frame_and_depth_are_accepted() {
        let (mut receiver, mut peer) = channel();
        let bytes = format!("\"{}\"", "x".repeat(MAX_FRAME_BYTES - 2));
        let writer = std::thread::spawn(move || raw(&mut peer, bytes.as_bytes()));
        assert_eq!(receiver.receive().unwrap().as_str().unwrap().len(), MAX_FRAME_BYTES - 2);
        writer.join().unwrap();
        let (mut receiver, mut peer) = channel();
        let bytes = format!("{}0{}", "[".repeat(MAX_NESTING), "]".repeat(MAX_NESTING));
        raw(&mut peer, bytes.as_bytes());
        assert!(receiver.receive().is_ok());
    }

    #[test]
    fn truncated_header_payload_and_disconnect_poison() {
        for bytes in [vec![], vec![0, 0], vec![0, 0, 0, 3, b'{']] {
            let (mut receiver, mut peer) = channel();
            peer.write_all(&bytes).unwrap();
            peer.shutdown(Shutdown::Write).unwrap();
            assert_eq!(receiver.receive(), Err(ChannelError::Io));
            assert_eq!(receiver.receive(), Err(ChannelError::Poisoned));
        }
        let (mut sender, peer) = channel();
        drop(peer);
        assert_eq!(sender.send(&json!(null)), Err(ChannelError::Io));
        assert_eq!(sender.send(&json!(null)), Err(ChannelError::Poisoned));
    }

    #[test]
    fn read_timeout_and_partial_frame_timeout_poison() {
        for partial in [false, true] {
            let (mut receiver, mut peer) = channel();
            if partial { peer.write_all(&[0, 0, 0, 2, b'{']).unwrap(); }
            assert_eq!(receiver.receive(), Err(ChannelError::Timeout));
            assert_eq!(receiver.send(&json!(null)), Err(ChannelError::Poisoned));
        }
    }

    #[test]
    fn nonreading_peer_eventually_hits_write_deadline() {
        let (mut sender, _peer) = channel();
        let value = json!("x".repeat(MAX_FRAME_BYTES - 2));
        let mut failed = false;
        for _ in 0..1024 {
            match sender.send(&value) {
                Ok(()) => {}
                Err(ChannelError::Timeout) => { failed = true; break; }
                other => panic!("unexpected write result: {other:?}"),
            }
        }
        assert!(failed, "nonreading peer never exhausted its socket buffer");
        assert_eq!(sender.receive(), Err(ChannelError::Poisoned));
    }

    #[test]
    fn oversize_or_deep_send_poison_without_reuse() {
        let (mut sender, _peer) = channel();
        assert_eq!(sender.send(&json!("x".repeat(MAX_FRAME_BYTES))), Err(ChannelError::InvalidFrame));
        assert_eq!(sender.send(&json!(null)), Err(ChannelError::Poisoned));
        let (mut sender, _peer) = channel();
        let mut value = json!(0);
        for _ in 0..=MAX_NESTING { value = Value::Array(vec![value]); }
        assert_eq!(sender.send(&value), Err(ChannelError::InvalidFrame));
        assert!(sender.is_poisoned());
    }

    #[test]
    fn zero_deadline_is_rejected() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        assert_eq!(FramedChannel::new(stream, (), Duration::ZERO, Duration::from_secs(1)).unwrap_err(), ChannelError::InvalidConfiguration);
    }
}
