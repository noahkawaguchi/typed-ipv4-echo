use crate::{
    endpoint::{Local, Remote},
    protocol::tcp::{SeqPoint, TcpFlags, TcpPayload},
};

/// Fields that differ when determining a segment to send.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SendInfo {
    pub(super) seq_num: SeqPoint<Local>,
    pub(super) ack_num: SeqPoint<Remote>,
    pub(super) flags: TcpFlags,
    pub(super) payload: Option<TcpPayload>,
}

impl SendInfo {
    pub(super) const fn pure_ack(seq_num: SeqPoint<Local>, ack_num: SeqPoint<Remote>) -> Self {
        Self { seq_num, ack_num, flags: TcpFlags::Ack, payload: None }
    }

    pub(super) const fn rst(seq_num: SeqPoint<Local>) -> Self {
        Self {
            seq_num,
            // ack_num is 0 because sending bare RST with no ACK flag leaves ack_num undefined
            ack_num: SeqPoint::new(0),
            flags: TcpFlags::Rst,
            payload: None,
        }
    }
}
