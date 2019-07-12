#![no_std]
use core::alloc::{GlobalAlloc, Layout};

mod os;
mod stats;
mod types;
mod options;
mod segment;
mod internal;
mod init;

pub struct Mimalloc;

// TODO: Implement this
unsafe impl GlobalAlloc for Mimalloc {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 { core::ptr::null_mut() }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}