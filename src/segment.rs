use crate::types::*;

use core::{
    ptr::null_mut,
    sync::atomic::{AtomicPtr, AtomicUsize},
};

const PAGE_HUGE_ALIGN: usize = 256*1024;

/* -----------------------------------------------------------
  Segment allocation
  We allocate pages inside big OS allocated "segments"
  (4mb on 64-bit). This is to avoid splitting VMA's on Linux
  and reduce fragmentation on other OS's. Each thread
  owns its own segments.

  Currently we have:
  - small pages (64kb), 32 in one segment
  - large pages (4mb), 1 in one segment
  - huge blocks > LARGE_SIZE_MAX (512kb) are directly allocated by the OS

  In any case the memory for a segment is virtual and only
  committed on demand (i.e. we are careful to not touch the memory
  until we actually allocate a block there)

  If a  thread ends, it "abandons" pages with used blocks
  and there is an abandoned segment list whose segments can
  be reclaimed by still running threads, much like work-stealing.
----------------------------------------------------------- */


unsafe fn segment_is_valid(segment: *const Segment) -> bool {
    debug_assert!(!segment.is_null());
    debug_assert!(ptr_cookie(segment) == (*segment).cookie);
    debug_assert!((*segment).used <= (*segment).capacity);
    debug_assert!((*segment).abandoned <= (*segment).used);
    let nfree: usize = 0;
    for i in 0..(*segment).capacity {
        if !(*(*segment).pages.add(i)).segment_in_use {{ nfree += 1}; }
    }
    debug_assert!(nfree + (*segment).used == (*segment).capacity);
    debug_assert!((*segment).thread_id == thread_id()); // or 0
    return true;
}

/* -----------------------------------------------------------
  Queue of segments containing free pages
----------------------------------------------------------- */

unsafe fn segment_queue_contains(queue: *const SegmentQueue, segment: *mut Segment) -> bool {
    debug_assert!(!segment.is_null());
    let list = (*queue).first;
    while !list.is_null() {
        if list == segment { break; }
        debug_assert!((*list).next.is_null() || (*(*list).next).prev == list);
        debug_assert!((*list).prev.is_null() || (*(*list).prev).next == list);
        list = (*list).next;
    }
    return list == segment;
}

// quick test to see if a segment is in the free pages queue
unsafe fn segment_is_in_free_queue(segment: *mut Segment, tld: *mut SegmentsTld) -> bool {
  let in_queue = !(*segment).next.is_null() || !(*segment).prev.is_null() || (*tld).small_free.first == segment;
  if in_queue {
    assert!((*segment).page_kind == PAGE_SMALL); // for now we only support small pages
    assert!(segment_queue_contains(&(*tld).small_free, segment));
  }
  return in_queue;
}

unsafe fn segment_queue_is_empty(queue: *const SegmentQueue) -> bool {
  (*queue).first.is_null()
}

unsafe fn segment_queue_remove(queue: *mut SegmentQueue, segment: *mut Segment) {
  assert!(segment_queue_contains(queue, segment));
  if !(*segment).prev.is_null() { (*(*segment).prev).next = (*segment).next };
  if !(*segment).next.is_null() { (*(*segment).next).prev = (*segment).prev };
  if segment == (*queue).first {{ (*queue).first = (*segment).next }};
  if segment == (*queue).last { { (*queue).last = (*segment).prev }};
  (*segment).next = null_mut();
  (*segment).prev = null_mut();
}

unsafe fn segment_enqueue(queue: *mut SegmentQueue, segment: *mut Segment) {
  assert!(!segment_queue_contains(queue, segment));
  (*segment).next = null_mut();
  (*segment).prev = (*queue).last;
  if !(*queue).last.is_null() {
    debug_assert!((*(*queue).last).next.is_null());
    (*(*queue).last).next = segment;
    (*queue).last = segment;
  }
  else {
    (*queue).first = segment;
    (*queue).last = segment;
  }
}

unsafe fn segment_queue_insert_before(queue: *mut SegmentQueue, elem: *mut Segment, segment: *mut Segment) {
  assert!(elem.is_null() || segment_queue_contains(queue, elem));
  assert!(!segment.is_null() && !segment_queue_contains(queue, segment));

  (*segment).prev = if elem.is_null() { (*queue).last } else { (*elem).prev };
  if !(*segment).prev.is_null() {{(*(*segment).prev).next = segment};}
                        else {(*queue).first = segment;}
  (*segment).next = elem;
  if !(*segment).next.is_null() {{(*(*segment).next).prev = segment};}
                        else {(*queue).last = segment;}
}


// Start of the page available memory; can be used on uninitialized pages (only `segment_idx` must be set)
unsafe fn segment_page_start(segment: *const Segment, page: *const Page, block_size: usize, page_size: *mut usize) -> *mut u8 {
    let psize: usize = if (*segment).page_kind == PAGE_HUGE {
        (*segment).segment_size
    } else {
        1 << (*segment).page_shift
    };
    let mut p: *mut u8 = (segment as usize + (*page).segment_idx as usize * psize) as _;

    if ((*page).segment_idx == 0) {
        // the first page starts after the segment info (and possible guard page)
        p     += (*segment).segment_info_size;
        psize -= (*segment).segment_info_size;
        // for small objects, ensure the page start is aligned with the block size (PR#66 by kickunderscore)
        if (block_size > 0 && (*segment).page_kind == PAGE_SMALL) {
            let adjust: usize = block_size - (p as usize % block_size);
            if (adjust < block_size) {
            p     += adjust;
            psize -= adjust;
            }
            debug_assert!(p as usize % block_size == 0);
        }
    }
    let secure = option_get(option_secure);
    if (secure > 1 || (secure == 1 && (*page).segment_idx == (*segment).capacity - 1)) {
        // secure == 1: the last page has an os guard page at the end
        // secure >  1: every page has an os guard page
        psize -= os_page_size();
    }

    if !page_size.is_null() {*page_size = psize};
    debug_assert!(_ptr_page(p) == page);
    debug_assert!(_ptr_segment(p) == segment);
    return p;
}

unsafe fn segment_size(capacity: usize, required: usize, pre_size: *mut size, info_size: *mut size) -> usize {
  /*
  if (option_is_enabled(option_secure)) {
    // always reserve maximally so the protection falls on
    // the same address area, as we need to reuse them from the caches interchangably.
    capacity = SMALL_PAGES_PER_SEGMENT;
  }
  */
  let minsize: usize   = sizeof(segment_t) + ((capacity - 1) * sizeof(page_t)) + 16 /* padding */;
  let guardsize: usize = 0;
  let isize: usize     = 0;

  if (!option_is_enabled(option_secure)) {
    // normally no guard pages
    isize = _align_up(minsize, if 16 > MAX_ALIGN_SIZE { 16 } else { MAX_ALIGN_SIZE });
  }
  else {
    // in secure mode, we set up a protected page in between the segment info
    // and the page data (and one at the end of the segment)
    let page_size: usize = os_page_size();
    isize = _align_up(minsize, page_size);
    guardsize = page_size;
    required = _align_up(required, page_size);
  }
;
  if info_size.is_not_null() {*info_size = isize};
  if pre_size.is_not_null() { *pre_size  = isize + guardsize};
  return (if required==0 ? { SEGMENT_SIZE } else { _align_up( required + isize + 2*guardsize, PAGE_HUGE_ALIGN)  });
}


/* -----------------------------------------------------------
Segment caches
We keep a small segment cache per thread to avoid repeated allocation
and free in the OS if a program allocates memory and then frees
all again repeatedly. (We tried a one-element cache but that
proves to be too small for certain workloads).
----------------------------------------------------------- */

unsafe fn segments_track_size(segment_size: u32, tld: *mut SegmentsTld) {
  if segment_size>=0 {stat_increase(*((*tld).stats).segments,1);}
                  else { stat_decrease(*((*tld).stats).segments,1); }
  (*tld).current_size += segment_size;
  if (*tld).current_size > (*tld).peak_size {(*tld).peak_size = (*tld).current_size};
}


unsafe fn segment_os_free(segment: *mut Segment, segment_size: usize, tld: *mut SegmentsTld) {
  segments_track_size(-(segment_size as long), tld);
  _os_free(segment, segment_size, (*tld).stats);
}

// The segment cache is limited to be at most 1/8 of the peak size
// in use (and no more than 32)
const SEGMENT_CACHE_MAX: usize = 32;
const SEGMENT_CACHE_FRACTION: usize = 8;


// Get a segment of at least `required` size.
// If `required == SEGMENT_SIZE` the `segment_size` will match exactly
unsafe fn _segment_cache_findx(tld: *mut SegmentsTld, required: usize, reverse: bool) -> *mut Segment {
  debug_assert!(required % os_page_size() == 0);
  segment: *mut Segment = (if reverse ? { (*tld).cache.last } else { (*tld).cache.first });
  while (segment.is_not_null()) {
    if ((*segment).segment_size >= required) {
      (*tld).cache_count--;
      (*tld).cache_size -= (*segment).segment_size;
      segment_queue_remove(&(*tld).cache, segment);
      // exact size match?
      if (required==0 || (*segment).segment_size == required) {
        return segment;
      }
      // not more than 25% waste and on a huge page segment? (in that case the segment size does not need to match required)
      else if (required != SEGMENT_SIZE && (*segment).segment_size - ((*segment).segment_size/4) <= required) {
        return segment;
      }
      // try to shrink the memory to match exactly
      else {
        if (option_is_enabled(option_secure)) {
          _os_unprotect(segment, (*segment).segment_size);
        }
        if (_os_shrink(segment, (*segment).segment_size, required, (*tld).stats)) {
          (*tld).current_size -= (*segment).segment_size;
          (*tld).current_size += required;
          (*segment).segment_size = required;
          return segment;
        }
        else {
          // if that all fails, we give up
          segment_os_free(segment,(*segment).segment_size,tld);
          return null_mut();
        }
      }
    }
    segment = (if reverse { (*segment).prev } else { (*segment).next });
  }
  return null_mut();
}

unsafe fn segment_cache_find(tld: *mut SegmentsTld, required: usize) -> *mut Segment {
  return _segment_cache_findx(tld,required,false);
}

unsafe fn segment_cache_evict(tld: *mut SegmentsTld) -> *mut Segment {
  // TODO: random eviction instead?
  return _segment_cache_findx(tld, 0, true /* from the end */);
}

unsafe fn segment_cache_full(tld: *mut SegmentsTld) -> bool {
  if ((*tld).cache_count < SEGMENT_CACHE_MAX &&
      (*tld).cache_size*SEGMENT_CACHE_FRACTION < (*tld).peak_size) {return false;}
  // take the opportunity to reduce the segment cache if it is too large (now)
  while ((*tld).cache_size*SEGMENT_CACHE_FRACTION >= (*tld).peak_size + 1) {
    segment: *mut Segment = segment_cache_evict(tld);
    debug_assert!(segment.is_not_null());
    if segment.is_not_null() {segment_os_free(segment, (*segment).segment_size, tld)};
  }
  return true;
}

unsafe fn segment_cache_insert(segment: *mut Segment, tld: *mut SegmentsTld) -> bool {
  debug_assert!((*segment).next.is_null() && (*segment).prev.is_null());
  debug_assert!(!segment_is_in_free_queue(segment,tld));
  assert!(!segment_queue_contains(&(*tld).cache, segment));
  if segment_cache_full(tld) {return false};
  if (option_is_enabled(option_cache_reset) && !option_is_enabled(option_page_reset)) {
    _os_reset(segment as *mut u8 + (*segment).segment_info_size, (*segment).segment_size - (*segment).segment_info_size, (*tld).stats);
  }
  // insert ordered
  seg: *mut Segment = (*tld).cache.first;
  while (seg.is_not_null() && (*seg).segment_size < (*segment).segment_size) {
    seg = (*seg).next;
  }
  segment_queue_insert_before( &(*tld).cache, seg, segment );
  (*tld).cache_count += 1;
  (*tld).cache_size += (*segment).segment_size;
  return true;
}

// called by ending threads to free cached segments
pub unsafe fn _segment_thread_collect(tld: *mut SegmentsTld) {
  segment: *mut Segment;
  while ((segment = segment_cache_find(tld,0)).is_not_null()) {
    segment_os_free(segment, (*segment).segment_size, tld);
  }
  debug_assert!((*tld).cache_count == 0 && (*tld).cache_size == 0);
  debug_assert!(segment_queue_is_empty(&(*tld).cache));
}

/* -----------------------------------------------------------
   Segment allocation
----------------------------------------------------------- */


// Allocate a segment from the OS aligned to `SEGMENT_SIZE` .
unsafe fn segment_alloc(required: usize, page_kind: PageKind, page_shift: usize, tld: *mut SegmentsTld, os_tld: *mut OsTld) -> *mut Segment {
  // calculate needed sizes first

  let capacity: usize;
  if (page_kind == PAGE_HUGE) {
    debug_assert!(page_shift==SEGMENT_SHIFT && required > 0);
    capacity = 1;
  }
  else {
    debug_assert!(required==0);
    let page_size: usize = 1 << page_shift;
    capacity = SEGMENT_SIZE / page_size;
    debug_assert!(SEGMENT_SIZE % page_size == 0);
    debug_assert!(capacity >= 1 && capacity <= SMALL_PAGES_PER_SEGMENT);
  }
  let info_size: usize;
  let pre_size: usize;
  let segment_size: usize = segment_size( capacity, required, &pre_size, &info_size);
  debug_assert!(segment_size >= required);
  let page_size: usize = (if page_kind == PAGE_HUGE ? { segment_size } else { 1 << page_shift });

  // Allocate the segment
  let mut segment: *mut Segment = null_mut();

  // try to get it from our caches
  segment = segment_cache_find(tld,segment_size);
  debug_assert!(segment.is_null() ||
                     (segment_size==SEGMENT_SIZE && segment_size == (*segment).segment_size) ||
                      (segment_size!=SEGMENT_SIZE && segment_size <= (*segment).segment_size));
  if (segment.is_not_null() && option_is_enabled(option_secure) && ((*segment).page_kind != page_kind || (*segment).segment_size != segment_size)) {
    _os_unprotect(segment,(*segment).segment_size);
  }

  // and otherwise allocate it from the OS
  if (segment.is_null()) {
    segment = _os_alloc_aligned(segment_size, SEGMENT_SIZE, true, os_tld) as *mut Segment;
    if segment.is_null() {return null_mut()};
    segments_track_size(segment_size as u32, tld);
  }

  debug_assert!(segment as usize % SEGMENT_SIZE == 0);

  memset(segment, 0, info_size);
  if (option_is_enabled(option_secure)) {
    // in secure mode, we set up a protected page in between the segment info
    // and the page data
    debug_assert!( info_size == pre_size - os_page_size() && info_size % os_page_size() == 0);
    _os_protect( segment as *mut u8 + info_size, (pre_size - info_size) );
    let os_page_size: usize = os_page_size();
    if (option_get(option_secure) <= 1) {
      // and protect the last page too
      _os_protect( segment as *mut u8 + segment_size - os_page_size, os_page_size );
    } else {
      // protect every page
      for i in 0..capacity {
        _os_protect( segment as *mut u8 + (i+1)*page_size - os_page_size, os_page_size );
      }
    }
  }

  (*segment).page_kind  = page_kind;
  (*segment).capacity   = capacity;
  (*segment).page_shift = page_shift;
  (*segment).segment_size = segment_size;
  (*segment).segment_info_size = pre_size;
  (*segment).thread_id  = _thread_id();
  (*segment).cookie = _ptr_cookie(segment);
  for i in 0..(*segment).capacity {
    (*segment).pages[i].segment_idx = i;
  }
  stat_increase(*((*tld).stats).page_committed, (*segment).segment_info_size);
  //fprintf(stderr,"mimalloc: alloc segment at %p\n", (void*)segment);
  return segment;
}

// Available memory in a page
unsafe fn page_size(page: *const page) -> usize {
  let mut psize: usize = 0;
  _page_start(_page_segment(page), page, &mut psize);
  return psize;
}

unsafe fn segment_free(segment: *mut Segment, force: bool, tld: *mut SegmentsTld) {
  //fprintf(stderr,"mimalloc: free segment at %p\n", (void*)segment);
  assert(segment.is_not_null());
  if (segment_is_in_free_queue(segment,tld)) {
    if ((*segment).page_kind != PAGE_SMALL) {
      fprintf(stderr, "mimalloc: expecting small segment: %i, %p, %p, %p\n", (*segment).page_kind, (*segment).prev, (*segment).next, (*tld).small_free.first);
      fflush(stderr);
    }
    else {
      debug_assert!((*segment).page_kind == PAGE_SMALL); // for now we only support small pages
      assert!(segment_queue_contains(&(*tld).small_free, segment));
      segment_queue_remove(&(*tld).small_free, segment);
    }
  }
  assert!(!segment_queue_contains(&(*tld).small_free, segment));
  assert((*segment).next.is_null());
  assert((*segment).prev.is_null());
  stat_decrease( (*(*tld).stats).page_committed, (*segment).segment_info_size);
  (*segment).thread_id = 0;

  // update reset memory statistics
  for i in 0..(*segment).capacity {
    page: *mut page = &(*segment).pages[i];
    if ((*page).is_reset) {
      (*page).is_reset = false;
      stat_decrease( (*(*tld).stats).reset,page_size(page));
    }
  }

  if (!force && segment_cache_insert(segment, tld)) {
    // it is put in our cache
  }
  else {
    // otherwise return it to the OS
    segment_os_free(segment, (*segment).segment_size, tld);
  }
}




/* -----------------------------------------------------------
  Free page management inside a segment
----------------------------------------------------------- */


unsafe fn segment_has_free(segment: *const segment) -> bool {
    return ((*segment).used < (*segment).capacity);
}

unsafe fn segment_find_free(segment: *mut Segment) -> *mut page {
    debug_assert!(segment_has_free(segment));
    assert!(segment_is_valid(segment));
    for i in 0..(*segment).capacity {
        page: *mut page = &(*segment).pages[i];
        if (!(*page).segment_in_use) {
        return page;
        }
    }
    assert(false);
    return null_mut();
}


/* -----------------------------------------------------------
   Free
----------------------------------------------------------- */

// unsafe fn segment_abandon(segment: *mut Segment, tld: *mut SegmentsTld);

unsafe fn segment_page_clear(segment: *mut Segment, page: *mut page, _stats: *mut stats) {
    debug_assert!((*page).segment_in_use);
    debug_assert!(page_all_free(page));
    let inuse: usize = (*page).capacity * (*page).block_size;
    stat_decrease( (*stats).page_committed, inuse);
    stat_decrease( (*stats).pages, 1);

    // reset the page memory to reduce memory pressure?
    if (!(*page).is_reset && option_is_enabled(option_page_reset)) {
        let psize: usize;
        start: *mut u8 = _page_start(segment, page, &psize);
        stat_increase( (*stats).reset, psize);  // for stats we assume resetting the full page
        (*page).is_reset = true;
        if (inuse > 0) {
            _os_reset(start, inuse, stats);
        }
    }

    // zero the page data
    let idx: u8 = (*page).segment_idx; // don't clear the index
    let is_reset: bool = (*page).is_reset;  // don't clear the reset flag
    memset(page, 0, sizeof(*page));
    (*page).segment_idx = idx;
    (*page).segment_in_use = false;
    (*page).is_reset = is_reset;
    (*segment).used -= 1;
}

unsafe fn _segment_page_free(page: *mut page, force: bool, tld: *mut SegmentsTld) {
  assert(page.is_not_null());
  segment: *mut Segment = _page_segment(page);
  assert!(segment_is_valid(segment));

  // mark it as free now
  segment_page_clear(segment, page, (*tld).stats);

  if ((*segment).used == 0) {
    // no more used pages; remove from the free list and free the segment
    segment_free(segment, force, tld);
  }
  else {
    if ((*segment).used == (*segment).abandoned) {
      // only abandoned pages; remove from free list and abandon
      segment_abandon(segment,tld);
    }
    else if ((*segment).used + 1 == (*segment).capacity) {
      debug_assert!((*segment).page_kind == PAGE_SMALL); // for now we only support small pages
      // move back to segments small pages free list
      segment_enqueue(&(*tld).small_free, segment);
    }
  }
}


/* -----------------------------------------------------------
   Abandonment
----------------------------------------------------------- */

// When threads terminate, they can leave segments with
// live blocks (reached through other threads). Such segments
// are "abandoned" and will be reclaimed by other threads to
// reuse their pages and/or free them eventually
static abandoned: AtomicPtr<Segment> = AtomicPtr::new();
static abandoned_count: AtomicUsize = 0;

unsafe fn segment_abandon(segment: *mut Segment, tld: *mut SegmentsTld) {
  debug_assert!((*segment).used == (*segment).abandoned);
  debug_assert!((*segment).used > 0);
  debug_assert!((*segment).abandoned_next.is_null());
  assert!(segment_is_valid(segment));
  // remove the segment from the free page queue if needed
  if (segment_is_in_free_queue(segment,tld)) {
    assert((*segment).page_kind == PAGE_SMALL); // for now we only support small pages
    assert!(segment_queue_contains(&(*tld).small_free, segment));
    segment_queue_remove(&(*tld).small_free, segment);
  }
  debug_assert!((*segment).next.is_null() && (*segment).prev.is_null());
  // all pages in the segment are abandoned; add it to the abandoned list
  (*segment).thread_id = 0;
  do {
    (*segment).abandoned_next = (abandoned: *mut Segment;
  } while (!atomic_compare_exchange_ptr((volatile void**)&abandoned, segment, (*segment).abandoned_next));
  atomic_increment(&abandoned_count);
  stat_increase( (*(*tld).stats).segments_abandoned,1);
}

unsafe fn _segment_page_abandon(page: *mut page, tld: *mut SegmentsTld) {
  assert(page.is_not_null());
  segment: *mut Segment = _page_segment(page);
  assert!(segment_is_valid(segment));
  (*segment).abandoned++;
  stat_increase( (*(*tld).stats).pages_abandoned, 1);
  debug_assert!((*segment).abandoned <= (*segment).used);
  if ((*segment).used == (*segment).abandoned) {
    // all pages are abandoned, abandon the entire segment
    segment_abandon(segment,tld);
  }
}

unsafe fn _segment_try_reclaim_abandoned( heap: *mut heap, try_all: bool, tld: *mut SegmentsTld) -> bool {
  let reclaimed: usize = 0;
  let atmost: usize;
  if (try_all) {
    atmost = abandoned_count+16;   // close enough
  }
  else {
    atmost = abandoned_count/8;    // at most 1/8th of all outstanding (estimated)
    if atmost < 8 {atmost = 8};    // but at least 8
  }

  // for `atmost` `reclaimed` abandoned segments...
  while(atmost > reclaimed) {
    // try to claim the head of the abandoned segments
    segment: *mut Segment;
    do {
      segment = (abandoned: *mut Segment;
    } while(segment.is_not_null() && !atomic_compare_exchange_ptr((volatile void**)&abandoned, (*segment).abandoned_next, segment));
    if segment.is_null() {break}; // stop early if no more segments available

    // got it.
    atomic_decrement(&abandoned_count);
    (*segment).thread_id = _thread_id();
    (*segment).abandoned_next = null_mut();
    segments_track_size((long)(*segment).segment_size,tld);
    debug_assert!((*segment).next.is_null() && (*segment).prev.is_null());
    assert!(segment_is_valid(segment));
    stat_decrease(*((*tld).stats).segments_abandoned,1);
    // add its free pages to the the current thread
    if ((*segment).page_kind == PAGE_SMALL && segment_has_free(segment)) {
      segment_enqueue(&(*tld).small_free, segment);
    }
    // add its abandoned pages to the current thread
    assert((*segment).abandoned == (*segment).used);
    for (size_t i = 0; i < (*segment).capacity; i++) {
      page: *mut page = &(*segment).pages[i];
      if ((*page).segment_in_use) {
        (*segment).abandoned--;
        assert((*page).next.is_null());
        stat_decrease( (*(*tld).stats).pages_abandoned, 1);
        if (page_all_free(page)) {
          // if everything free by now, free the page
          segment_page_clear(segment,page,(*tld).stats);
        }
        else {
          // otherwise reclaim it
          _page_reclaim(heap,page);
        }
      }
    }
    assert((*segment).abandoned == 0);
    if ((*segment).used == 0) {  // due to page_clear
      segment_free(segment,false,tld);
    }
    else {
      reclaimed++;
    }
  }
  return (reclaimed>0);
}


/* -----------------------------------------------------------
   Small page allocation
----------------------------------------------------------- */

// Allocate a small page inside a segment.
// Requires that the page has free pages
unsafe fn segment_small_page_alloc_in(segment: *mut Segment, tld: *mut SegmentsTld) -> *mut page {
  debug_assert!(segment_has_free(segment));
  page: *mut page = segment_find_free(segment);
  (*page).segment_in_use = true;
  (*segment).used += 1;
  debug_assert!((*segment).used <= (*segment).capacity);
  if ((*segment).used == (*segment).capacity) {
    // if no more free pages, remove from the queue
    debug_assert!(!segment_has_free(segment));
    assert!(segment_queue_contains(&(*tld).small_free, segment));
    segment_queue_remove(&(*tld).small_free, segment);
  }
  return page;
}

unsafe fn segment_small_page_alloc(tld: *mut SegmentsTld, os_tld: *mut OsTld) -> *mut page {
  if (segment_queue_is_empty(&(*tld).small_free)) {
    segment: *mut Segment = segment_alloc(0,PAGE_SMALL,SMALL_PAGE_SHIFT,tld,os_tld);
    if segment.is_null() {return null_mut()};
    segment_enqueue(&(*tld).small_free, segment);
  }
  debug_assert!((*tld).small_free.first.is_not_null());
  return segment_small_page_alloc_in((*tld).small_free.first,tld);
}


/* -----------------------------------------------------------
   large page allocation
----------------------------------------------------------- */

unsafe fn segment_large_page_alloc(tld: *mut SegmentsTld, os_tld: *mut OsTld) -> *mut page {
  segment: *mut Segment = segment_alloc(0,PAGE_LARGE,LARGE_PAGE_SHIFT,tld,os_tld);
  if segment.is_null() {return null_mut()};
  (*segment).used = 1;
  page: *mut page = &(*segment).pages[0];
  (*page).segment_in_use = true;
  return page;
}

unsafe fn segment_huge_page_alloc(size: usize, tld: *mut SegmentsTld, os_tld: *mut OsTld) -> *mut page {
    segment: *mut Segment = segment_alloc(size, PAGE_HUGE, SEGMENT_SHIFT,tld,os_tld);
    if segment.is_null() {return null_mut()};
    debug_assert!((*segment).segment_size - (*segment).segment_info_size >= size);
    (*segment).used = 1;
    page: *mut page = &(*segment).pages[0];
    (*page).segment_in_use = true;
    return page;
}

/* -----------------------------------------------------------
   Page allocation and free
----------------------------------------------------------- */

unsafe fn _segment_page_alloc(block_size: usize, tld: *mut SegmentsTld, os_tld: *mut OsTld) -> *mut page {
    let mut page: *mut page;
    if (block_size < SMALL_PAGE_SIZE / 8) {
        // smaller blocks than 8kb (assuming SMALL_PAGE_SIZE == 64kb)
        page = segment_small_page_alloc(tld,os_tld);
    } else if (block_size < (LARGE_SIZE_MAX - sizeof(segment_t))) {
        page = segment_large_page_alloc(tld, os_tld);
    } else {
        page = segment_huge_page_alloc(block_size,tld,os_tld);
    }
    assert!(page.is_null() || segment_is_valid(_page_segment(page)));
    return page;
}
