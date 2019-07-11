use crate::types::*;
use core::sync::atomic::Ordering;

pub fn _stat_increase(stat: *mut StatCount, amount: i64) {
    _stat_update(stat, amount);
}

pub fn _stat_decrease(stat: *mut StatCount, amount: i64) {
    _stat_update(stat, -amount);
}

pub fn _stat_update(stat: *mut StatCount, amount: i64) {
    if amount == 0 { return; }
    let current = (*stat).current.fetch_add(amount, Ordering::Relaxed);
    
    // (*stat).peak.fetch_max(current, Ordering::Relaxed); // TODO: Use this once it's on stable
    let old_peak = (*stat).peak.load(Ordering::Relaxed);
    if current > old_peak {
        (*stat).peak.compare_and_swap(old_peak, current, Ordering::Relaxed);
    }

    if amount > 0 {
        (*stat).allocated.fetch_add(amount, Ordering::Relaxed);
    } else {
        (*stat).freed.fetch_add(-amount, Ordering::Relaxed);
    }
}