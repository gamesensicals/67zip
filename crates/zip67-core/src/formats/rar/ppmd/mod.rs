//! PPMd var.H, the text model RAR 2.9-4.x uses for its PPM blocks.
//!
//! Vendored from the `ppmd-rust` crate 1.5.2 (CC0-1.0 OR MIT-0), a safe
//! Rust port of Igor Pavlov's public domain PPMd code from 7-Zip, itself
//! based on Dmitry Shkarin's PPMd var.H. Changed for 67zip: only the
//! decoder with the carryless range coder is kept, and the range coder
//! reads from the RAR bit stream through [`ByteSource`] and can be
//! restarted while the model is kept, as RAR requires.
#![allow(dead_code, clippy::all, clippy::pedantic)]

mod memory;
mod model;
mod range;

pub(crate) use model::PPMd7;
pub(crate) use range::RangeDecoder7a;

/// Where the range decoder gets its bytes from.
pub(crate) trait ByteSource {
    fn next_byte(&mut self) -> u8;
}

pub(crate) const SYM_END: i32 = -1;
pub(crate) const SYM_ERROR: i32 = -2;
pub(crate) const PPMD7_MIN_ORDER: u32 = 2;
pub(crate) const PPMD7_MAX_ORDER: u32 = 64;

pub(crate) enum Error {
    RangeDecoderInitialization,
    InvalidParameter,
    IoError(std::io::Error),
    MemoryAllocation,
}

use memory::{CtxRef, Memory, STATE_SIZE, StateRef, Successor, UNIT_SIZE, UnitRef};

const PPMD_INT_BITS: u32 = 7;
const PPMD_PERIOD_BITS: u32 = 7;
const PPMD_BIN_SCALE: u32 = 1 << (PPMD_INT_BITS + PPMD_PERIOD_BITS);

const fn ppmd_get_mean_spec(summ: u32, shift: u32, round: u32) -> u32 {
    (summ + (1 << (shift - round))) >> shift
}

const fn ppmd_get_mean(summ: u32) -> u32 {
    ppmd_get_mean_spec(summ, PPMD_PERIOD_BITS, 2)
}

const fn ppmd_update_prob_1(prob: u32) -> u32 {
    prob - ppmd_get_mean(prob)
}

const PPMD_N1: u32 = 4;
const PPMD_N2: u32 = 4;
const PPMD_N3: u32 = 4;
const PPMD_N4: u32 = (128 + 3 - PPMD_N1 - 2 * PPMD_N2 - 3 * PPMD_N3) / 4;
const PPMD_NUM_INDEXES: u32 = PPMD_N1 + PPMD_N2 + PPMD_N3 + PPMD_N4;

enum SeeSource {
    Dummy,
    Table(usize, usize),
}

#[derive(Copy, Clone, Default)]
#[repr(C, packed)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    fn update(&mut self) {
        if (self.shift as i32) < 7 && {
            self.count = self.count.wrapping_sub(1);
            self.count as i32 == 0
        } {
            self.summ = ((self.summ as i32) << 1) as u16;
            let fresh = self.shift;
            self.shift = self.shift.wrapping_add(1);
            self.count = (3 << fresh as i32) as u8;
        }
    }
}
