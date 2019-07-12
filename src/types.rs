use core::{
    mem::size_of,
    sync::atomic::{AtomicI64, AtomicPtr, AtomicUsize},
};

#[cfg(target_pointer_width = "64")]
pub const MI_INTPTR_SHIFT: usize = 3;
#[cfg(target_pointer_width = "32")]
pub const MI_INTPTR_SHIFT: usize = 2;

pub const MI_INTPTR_SIZE: usize = 1 << MI_INTPTR_SHIFT;


// ------------------------------------------------------
// Main internal data-structures
// ------------------------------------------------------

// Main tuning parameters for segment and page sizes
// Sizes for 64-bit, divide by two for 32-bit
pub const MI_SMALL_PAGE_SHIFT: usize =        13 + MI_INTPTR_SHIFT;      // 64kb
pub const MI_LARGE_PAGE_SHIFT: usize =         6 + MI_SMALL_PAGE_SHIFT;  // 4mb
pub const MI_SEGMENT_SHIFT: usize =            MI_LARGE_PAGE_SHIFT;      // 4mb

// Derived constants
pub const MI_SEGMENT_SIZE: usize =            1 << MI_SEGMENT_SHIFT;
pub const MI_SEGMENT_MASK: usize =            MI_SEGMENT_SIZE - 1;

pub const MI_SMALL_PAGE_SIZE: usize =         1 << MI_SMALL_PAGE_SHIFT;
pub const MI_LARGE_PAGE_SIZE: usize =         1 << MI_LARGE_PAGE_SHIFT;

pub const MI_SMALL_PAGES_PER_SEGMENT: usize = MI_SEGMENT_SIZE / MI_SMALL_PAGE_SIZE;
pub const MI_LARGE_PAGES_PER_SEGMENT: usize = MI_SEGMENT_SIZE / MI_LARGE_PAGE_SIZE;

pub const MI_LARGE_SIZE_MAX: usize =          MI_LARGE_PAGE_SIZE / 8;   // 512kb on 64-bit
pub const MI_LARGE_WSIZE_MAX: usize =         MI_LARGE_SIZE_MAX >> MI_INTPTR_SHIFT;

pub const MI_SMALL_WSIZE_MAX: usize = 128;
pub const MI_SMALL_SIZE_MAX: usize =  MI_SMALL_WSIZE_MAX * size_of::<*mut ()>();


// Maximum number of size classes. (spaced exponentially in 16.7% increments)
pub const MI_BIN_HUGE: usize = 64;

pub const MI_BIN_FULL: usize = MI_BIN_HUGE + 1;

// Minimal alignment necessary. On most platforms 16 bytes are needed
// due to SSE registers for example. This must be at least `MI_INTPTR_SIZE`
pub const MI_MAX_ALIGN_SIZE: usize = 16;   // sizeof(max_align_t)

pub struct Block {
    pub next: usize,
}

pub enum Delayed {
    NO_DELAYED_FREE = 0,
    USE_DELAYED_FREE = 1,
    DELAYED_FREEING = 2,
}

pub use Delayed::*;

pub union PageFlags {
    value: u16,
    inner: PageFlagsInner,
}

#[derive(Clone, Copy)]
pub struct PageFlagsInner {
    has_aligned: bool,
    is_full: bool,
}

// Thread free list.
// We use bottom 2 bits of the pointer for the `use_delayed_free` and `delayed_freeing` flags.
pub struct ThreadFree { value: AtomicUsize, }

pub struct Page {
    // "owned" by the segment
    pub segment_idx: u8,                           // index in the segment `pages` array, `page == &segment->pages[page->segment_idx]`
    pub segment_in_use: bool,                      // `true` if the segment allocated this page
    pub is_reset: bool,                            // `true` if the page memory was reset

    // layout like this to optimize access in `mi_malloc` and `mi_free`
    pub flags: PageFlags,
    pub capacity: u16,                             // number of blocks committed
    pub reserved: u16,                             // numbes of blocks reserved in memory

    pub free: *mut Block,                          // list of available free blocks (`malloc` allocates from this list)
    pub cookie: usize,                             // random cookie to encode the free lists
    pub used: usize,                               // number of blocks in use (including blocks in `local_free` and `thread_free`)

    pub local_free: *mut Block,                    // list of deferred free blocks by this thread (migrates to `free`)
    pub thread_freed: AtomicUsize,                 // at least this number of blocks are in `thread_free`
    pub thread_free: ThreadFree,                   // list of deferred free blocks freed by other threads

    // less accessed info
    pub block_size: usize,                         // size available in each block (always `>0`)
    pub heap: *mut Heap,                           // the owning heap
    pub next: *mut Page,                           // next page owned by this thread with the same `block_size`
    pub prev: *mut Page,                           // previous page owned by this thread with the same `block_size`
}

#[derive(PartialEq)]
pub enum PageKind {
    PAGE_SMALL,    // small blocks go into 64kb pages inside a segment
    PAGE_LARGE,    // larger blocks go into a single page spanning a whole segment
    PAGE_HUGE,     // huge blocks (>512kb) are put into a single page in a segment of the exact size (but still 2mb aligned)
}

pub use PageKind::*;

// Segments are large allocated memory blocks (2mb on 64 bit) from
// the OS. Inside segments we allocated fixed size _pages_ that
// contain blocks.
pub struct Segment {
    pub next: *mut Segment,
    pub prev: *mut Segment,
    pub abandoned_next: *mut Segment,
    pub abandoned: usize,   // abandoned pages (i.e. the original owning thread stopped) (`abandoned <= used`)
    pub used: usize,        // count of pages in use (`used <= capacity`)
    pub capacity: usize,    // count of available pages (`#free + used`)
    pub segment_size: usize,// for huge pages this may be different from `MI_SEGMENT_SIZE`
    pub segment_info_size: usize,  // space we are using from the first page for segment meta-data and possible guard pages.
    pub cookie: usize,      // verify addresses in debug mode: `mi_ptr_cookie(segment) == segment->cookie`

    // layout like this to optimize access in `mi_free`
    pub page_shift: usize,  // `1 << page_shift` == the page sizes == `page->block_size * page->reserved` (unless the first page, then `-segment_info_size`).
    pub thread_id: usize,   // unique id of the thread owning this segment
    pub page_kind: PageKind,   // kind of pages: small, large, or huge
    pub pages: *mut Page,    // up to `MI_SMALL_PAGES_PER_SEGMENT` pages
}

// Pages of a certain block size are held in a queue.
pub struct PageQueue {
    pub first: *mut Page,
    pub last: *mut Page,
    pub block_size: usize,
}

// A heap owns a set of pages.
pub struct Heap {
    pub tld:                  *mut Tld,
    pub pages_free_direct:    [*mut Page; MI_SMALL_WSIZE_MAX + 2],   // optimize: array where every entry points a page with possibly free blocks in the corresponding queue for that size.
    pub pages:                [PageQueue; MI_BIN_FULL + 1],          // queue of pages for each size class (or "bin")
    pub thread_delayed_free:  AtomicPtr<Block>,
    pub thread_id:            usize,                                 // thread this heap belongs too
    pub cookie:               usize,
    pub random:               usize,                                 // random number used for secure allocation
    pub page_count:           usize,                                 // total number of pages in the `pages` queues.
    pub no_reclaim:           bool,                                  // `true` if this heap should not reclaim abandoned pages
}

// ------------------------------------------------------
// Statistics
// ------------------------------------------------------

pub struct StatCount {
    pub allocated: AtomicI64,
    pub freed: AtomicI64,
    pub peak: AtomicI64,
    pub current: AtomicI64,
} 

pub struct StatCounter {
    pub total: AtomicI64,
    pub count: AtomicI64,
}

pub struct Stats {
    pub segments: StatCount,
    pub pages: StatCount,
    pub reserved: StatCount,
    pub committed: StatCount,
    pub reset: StatCount,
    pub page_committed: StatCount,
    pub segments_abandoned: StatCount,
    pub pages_abandoned: StatCount,
    pub pages_extended: StatCount,
    pub mmap_calls: StatCount,
    pub mmap_right_align: StatCount,
    pub mmap_ensure_aligned: StatCount,
    pub commit_calls: StatCount,
    pub threads: StatCount,
    pub huge: StatCount,
    pub malloc: StatCount,
    pub searches: StatCounter,
    #[cfg(stats)]
    pub normal: [StatCount; MI_BIN_HUGE + 1],
}

// ------------------------------------------------------
// Thread Local data
// ------------------------------------------------------

// Queue of segments
pub struct SegmentQueue {
    pub first: *mut Segment,
    pub last:  *mut Segment,
}

// Segments thread local data
pub struct SegmentsTld {
    pub small_free:    SegmentQueue,  // queue of segments with free small pages
    pub current_size:  usize,         // current size of all segments
    pub peak_size:     usize,         // peak size of all segments
    pub cache_count:   usize,         // number of segments in the cache
    pub cache_size:    usize,         // total size of all segments in the cache
    pub cache:         SegmentQueue,  // (small) cache of segments for small and large pages (to avoid repeated mmap calls)
    pub stats:         *mut Stats,    // points to tld stats
}

// OS thread local data
pub struct OsTld {
    pub mmap_next_probable:  usize,       // probable next address start allocated by mmap (to guess which path to take on alignment)
    pub mmap_previous:       *mut (),     // previous address returned by mmap
    pub pool:                *mut u8,     // pool of segments to reduce mmap calls on some platforms
    pub pool_available:      usize,       // bytes available in the pool
    pub stats:           *mut Stats,  // points to tld stats
}

// Thread local data
pub struct Tld {
    pub heartbeat:     u64,          // monotonic heartbeat count
    pub heap_backing:  *mut Heap,    // backing heap of this thread (cannot be deleted)
    pub segments:      SegmentsTld,  // segment tld
    pub os:            OsTld,        // os tld
    pub stats:         Stats,        // statistics
}