use crate::types::*;
use crate::init::*;

use core::mem::size_of;

// Overflow detecting multiply
const MI_MUL_NO_OVERFLOW: usize = 1 << (4 * size_of::<usize>());  // sqrt(SIZE_MAX)
#[inline]
fn mul_overflow(size: usize, count: usize, total: &mut usize) -> bool {
    *total = size * count;
    (size >= MI_MUL_NO_OVERFLOW || count >= MI_MUL_NO_OVERFLOW)
            && size > 0 && (usize::max_value() / size) < count
}

// Align a byte size to a size in _machine words_,
// i.e. byte size == `wsize*sizeof(void*)`.
#[inline]
fn wsize_from_size(size: usize) -> usize {
  debug_assert!(size <= usize::max_value() - size_of::<usize>());
  (size + size_of::<usize>() - 1) / size_of::<usize>()
}

#[inline]
fn get_default_heap() -> *mut Heap {
    // on some platforms, like macOS, the dynamic loader calls `malloc`
    // to initialize thread local data. To avoid recursion, we need to avoid
    // accessing the thread local `_default_heap` until our module is loaded
    // and use the statically allocated main heap until that time.
    // TODO: patch ourselves dynamically to avoid this check every time?
    #[cfg(MI_TLS_RECURSE_GUARD)]
    {
        if !_process_is_initialized { return &_heap_main; }
    }
    return _heap_default;
}

#[inline]
fn heap_is_default(heap: *const Heap) -> bool {
    heap == get_default_heap()
}

#[inline]
fn heap_is_backing(heap: *const Heap) -> bool {
    (*(*heap).tld).heap_backing as *const _ == heap
}

#[inline]
fn heap_is_initialized(heap: *mut Heap) -> bool {
    debug_assert!(heap != NULL);
    heap != &_heap_empty
}

#[inline]
fn heap_get_free_small_page(heap: *mut Heap, size: usize) -> *mut Page {
    debug_assert!(size <= MI_SMALL_SIZE_MAX);
    return (*heap).pages_free_direct[_wsize_from_size(size)];
}

// Get the page belonging to a certain size class
#[inline]
fn get_free_small_page(size: usize) -> *mut Page {
    return _heap_get_free_small_page(get_default_heap(), size);
}


// Segment that contains the pointer
#[inline]
fn ptr_segment(p: *const u8) -> *mut Segment {
    // debug_assert!(p != NULL);
    p as usize & !MI_SEGMENT_MASK as _
}

// Segment belonging to a page
#[inline]
fn page_segment(page: *const Page) -> *mut Segment {
    let segment: *mut Segment = _ptr_segment(page);
    debug_assert!(segment == NULL || page == &segment->pages[page->segment_idx]);
    return segment;
}

// Get the page containing the pointer
#[inline]
fn segment_page_of(segment: *const Segment, p: *const u8) -> *mut Page {
    // if (segment->page_size > MI_SEGMENT_SIZE) return &segment->pages[0];  // huge pages
    let diff: usize = (uint8_t*)p - (uint8_t*)segment;
    debug_assert!(diff >= 0 && diff < MI_SEGMENT_SIZE);
    uintptr_t idx = (uintptr_t)diff >> segment->page_shift;
    debug_assert!(idx < segment->capacity);
    debug_assert!(segment->page_kind == MI_PAGE_SMALL || idx == 0);
    return &((segment_t*)segment)->pages[idx];
}

// Quick page start for initialized pages
#[inline]
fn page_start(segment: *const segment_t, page: *const page_t, page_size: *mut usize) -> *mut u8 {
    return _segment_page_start(segment, page, (*page).block_size, page_size);
}

// Get the page containing the pointer
#[inline]
fn ptr_page(p: *mut u8) -> *mut Page {
    return _segment_page_of(_ptr_segment(p), p);
}

// are all blocks in a page freed?
#[inline]
fn page_all_free(page: *const page_t) -> bool {
    debug_assert!(page != NULL);
    return (page->used - page->thread_freed == 0);
}

// are there immediately available blocks
#[inline]
fn page_immediate_available(page: *const page_t) -> bool {
    debug_assert!(page != NULL);
    return (page->free != NULL);
}

// are there free blocks in this page?
#[inline]
fn page_has_free(page: *mut Page) -> bool {
    debug_assert!(page != NULL);
    let hasfree: bool = (page_immediate_available(page) || (*page).local_free != NULL || ((*page).thread_free.head != 0));
    debug_assert!(hasfree || (*page).used - (*page).thread_freed == (*page).capacity);
    return hasfree;
}

// are all blocks in use?
#[inline]
fn page_all_used(page: *mut Page) -> bool {
    debug_assert!(page != NULL);
    return !page_has_free(page);
}

// is more than 7/8th of a page in use?
#[inline]
fn page_mostly_used(page: *const Page) -> bool {
    if page.is_null() { return true; }
    let frac: u16 = (*page).reserved / 8;
    return (*page).reserved - (*page).used + (*page).thread_freed < frac;
}

#[inline]
fn page_queue(heap: *mut Heap, size: usize) -> *mut PageQueue {
    return &mut (*heap).pages[_bin(size)];
}

// -------------------------------------------------------------------
// Encoding/Decoding the free list next pointers
// -------------------------------------------------------------------

fn block_nextx(cookie: usize, block: *mut Block) -> *mut Block {
    #[cfg(MI_SECURE)]
    {
        ((*block).next ^ cookie) as _
    }
    #[cfg(not(MI_SECURE))]
    {
        (*block).next as _
    }
}

fn block_set_nextx(cookie: usize, block: *mut Block, next: *mut Block) {
    #[cfg(MI_SECURE)]
    {
        (*block).next = next as _ ^ cookie;
    }
    #[cfg(not(MI_SECURE))]
    {
        (*block).next = next as _;
    }
}

fn block_next(page: *mut Page, block: *mut Block) -> *mut Block {
    block_nextx((*page).cookie, block)
}

fn block_set_next(page: *mut Page, block: *mut Block, next: *mut Block) {
    block_set_nextx((*page).cookie, block, next);
}

#[inline]
pub fn thread_id() -> usize {
    // -------------------------------------------------------------------
    // Getting the thread id should be performant
    // as it is called in the fast path of `_free`,
    // so we specialize for various platforms.
    // -------------------------------------------------------------------
    // TODO: Uncomment this when function gets added to winapi
    // #[cfg(windows)]
    // {
    //     // Windows: works on Intel and ARM in both 32- and 64-bit
    //     NtCurrentTeb() as usize
    // }

    // TLS register on x86 is in the FS or GS register
    // see: https://akkadia.org/drepper/tls.pdf
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64"),
        not(windows)
    ))]
    {
        let tid;
        #[cfg(target_arch = "x86")]
        {asm!("movl %%gs:0, %0" : "=r" (tid) : : );}  // 32-bit always uses GS
        #[cfg(all(target_arch = "x86_64", target_os = "mac"))]
        {asm!("movq %%gs:0, %0" : "=r" (tid) : : );}  // x86_64 macOS uses GS
        #[cfg(all(target_arch = "x86_64", not(target_os = "mac")))]
        {asm!("movq %%fs:0, %0" : "=r" (tid) : : );}  // x86_64 Linux, BSD uses FS
        #[cfg(target_arch = "arm")]
        {asm!("mrc p15, 0, %0, c13, c0, 3" : "=r" (tid));}
        #[cfg(target_arch = "aarch64")]
        {asm!("mrs %0, tpidr_el0" : "=r" (tid));}
        tid
    }

    // otherwise use standard C
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64")))]
    {
        &_heap_default as usize
    }
    unimplemented!()
}
