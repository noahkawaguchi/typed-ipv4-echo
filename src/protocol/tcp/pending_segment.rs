use {
    crate::protocol::tcp::{SendInfo, SeqDist, SeqPoint, TcpFlags},
    std::time::{Duration, Instant},
};

/// A sent segment that consumed sequence numbers and hasn't yet been acknowledged.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct PendingSegment {
    /// The values and data the segment was sent with, frozen at send time.
    send_info: SendInfo,

    /// The sequence number one past the last byte/flag consumed by the segment (`seq_num +
    /// consumed`, e.g. `seq_num + 1` for a SYN/FIN, `seq_num + payload.len()` for data). Compared
    /// against an incoming `ack_num` to tell whether the segment has been fully acknowledged.
    end_seq: SeqPoint,

    /// The last time at which the segment was sent.
    last_sent_at: Instant,

    /// The number of times the segment has been retransmitted.
    retries: u8,
}

impl PendingSegment {
    /// Creates a new unacked segment eligible for retransmission, covering the sequence numbers
    /// consumed by the segment.
    pub(super) fn new(send_info: SendInfo, sent_at: Instant) -> Self {
        let end_seq = send_info
            .seq_num
            // Any SYN/FIN consumes a single phantom byte
            + SeqDist::new(u32::from(matches!(
                send_info.flags,
                TcpFlags::Syn | TcpFlags::SynAck | TcpFlags::FinAck
            )))
            // A payload consumes the number of bytes in the payload
            + SeqDist::new(u32::from(send_info.payload.as_ref().map_or(0, |p| p.len().get())));

        Self { send_info, end_seq, last_sent_at: sent_at, retries: 0 }
    }

    /// Returns the time at which the segment is due for retransmission using exponential backoff,
    /// or `Instant::now()` if `Instant` overflowed.
    pub(super) fn time_due(&self, initial_rto: Duration) -> Instant {
        // Make the RTO saturate at `Duration::MAX`, or "about 584,942,417,355 years" (std library
        // docs), leaving plenty of room for any real RTO.
        let rto = initial_rto.saturating_mul(2u32.saturating_pow(self.retries.into()));

        // In practice, adding `Duration::MAX` should overflow any `Instant`, but this is not
        // guaranteed since `Instant` is opaque. Therefore, check for overflow separately.
        //
        // Return due now on overflow so that a pending segment cannot get stuck never being due.
        self.last_sent_at
            .checked_add(rto)
            .unwrap_or_else(Instant::now)
    }

    /// Returns whether the segment is fully covered by `ack_num`.
    pub(super) fn is_covered_by(&self, ack_num: SeqPoint) -> bool { self.end_seq <= ack_num }

    /// Returns whether the segment has been retried at least `max_retries` times.
    pub(super) const fn exhausted_retries(&self, max_retries: u8) -> bool {
        self.retries >= max_retries
    }

    /// Clones the segment's `SendInfo` for retransmission and records that it is being
    /// retransmitted `now`.
    pub(super) fn retransmit_info(&mut self, now: Instant) -> SendInfo {
        self.retries = self.retries.saturating_add(1);
        self.last_sent_at = now;
        self.send_info.clone()
    }

    /// Returns a reference to the segment's `SendInfo` without recording a retransmission.
    #[cfg(test)]
    pub(super) const fn peek_info(&self) -> &SendInfo { &self.send_info }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{Result, protocol::tcp::tests::payload_from},
    };

    #[test]
    fn reports_due_now_on_overflow() -> Result {
        assert!(
            PendingSegment::new(
                SendInfo {
                    seq_num: SeqPoint::new(42),
                    ack_num: SeqPoint::new(24),
                    flags: TcpFlags::Ack,
                    payload: payload_from("Hello")?
                },
                Instant::now()
            )
            .time_due(Duration::MAX)
                <= Instant::now()
        );

        Ok(())
    }
}
