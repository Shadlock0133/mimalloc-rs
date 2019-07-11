#[cfg(not(windows))]
use libc::{mmap, munmap, mprotect, madvise, MADV_DONTNEED, PROT_NONE, PROT_READ, PROT_WRITE};
// #[cfg(windows)]
use winapi::{
    shared::{
        minwindef::{ULONG, FALSE},
        minwindef::*,
        ntdef::*,
        winerror::ERROR_SUCCESS,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        libloaderapi::{LoadLibraryA, GetProcAddress, FreeLibrary},
        memoryapi::{GetLargePageMinimum, VirtualAlloc, VirtualFree, VirtualProtect},
        processthreadsapi::*,
        securitybaseapi::AdjustTokenPrivileges,
        sysinfoapi::*,
        winbase::LookupPrivilegeValueA,
        winnt::{
            MEM_EXTENDED_PARAMETER, MEM_EXTENDED_PARAMETER_TYPE, MEM_ADDRESS_REQUIREMENTS,
            MEM_RELEASE, MEM_RESERVE, MEM_COMMIT, MEM_DECOMMIT, MEM_LARGE_PAGES,
            MEM_RESET,
            PAGE_READWRITE, PAGE_NOACCESS,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY, TOKEN_PRIVILEGES,
            SE_PRIVILEGE_ENABLED,
        },
    },
};

use log::warn;
use core::{ptr::null_mut};
use crate::{
    stats::*,
    types::*,
    options::*,
};

// page size (initialized properly in `os_init`)
static mut _os_page_size: usize = 4096;

// minimal allocation granularity
static os_alloc_granularity: usize = 4096;

// if non-zero, use large page allocation
static mut large_os_page_size: usize = 0;

fn align_up(size: usize, align: usize) -> usize {
    let mut x = (size / align) * align;
    if x < size { x += align; }
    if x < size { return 0; }
    x
}

fn align_down(size: usize, align: usize) -> usize {
    (size / align) * align
}

fn align_up_ptr(ptr: *mut u8, align: usize) -> *mut u8 {
    let size = ptr as usize;
    let mut x = (size / align) * align;
    if x < size { x += align; }
    if x < size { x = 0; }
    x as _
}

fn align_down_ptr(ptr: *mut u8, align: usize) -> *mut u8 {
    ((ptr as usize / align) * align) as _
}

// OS (small) page size
unsafe fn os_page_size() -> usize {
    _os_page_size
}

// if large OS pages are supported (2 or 4MiB), then return the size, otherwise return the small page size (4KiB)
unsafe fn os_large_page_size() -> usize {
    if large_os_page_size != 0 { large_os_page_size } else { os_page_size() }
}

fn use_large_os_page(size: usize, align: usize) -> bool {
  // if we have access, check the size and alignment requirements
  if large_os_page_size == 0 { return false; }
  (size % large_os_page_size) == 0 && (align % large_os_page_size) == 0
}

// round to a good allocation size
fn os_good_alloc_size(size: usize, _align: usize) -> usize {
    if size >= (usize::max_value() - os_alloc_granularity) { return size; } // possible overflow?
    align_up(size, os_alloc_granularity)
}

#[cfg(windows)]
type VirtualAlloc2Ptr = extern "stdcall" fn(HANDLE, LPVOID, ULONGLONG, ULONG, ULONG, *mut MEM_EXTENDED_PARAMETER, ULONG) -> LPVOID;
#[cfg(windows)]
static mut pVirtualAlloc2: VirtualAlloc2Ptr = null_mut();

#[cfg(windows)]
fn os_init() {
    // get the page size
    let si: SYSTEM_INFO = Default::default();
    GetSystemInfo(&mut si);
    if si.dwPageSize > 0 {_os_page_size = si.dwPageSize as _;}
    if si.dwAllocationGranularity > 0 {os_alloc_granularity = si.dwAllocationGranularity as _;}
    // get the VirtualAlloc2 function
    let hDll: HINSTANCE;
    hDll = LoadLibraryA(b"kernelbase.dll\0" as *const u8 as _);
    if !hDll.is_null() {
        // use VirtualAlloc2FromApp as it is available to Windows store apps
        pVirtualAlloc2 = GetProcAddress(hDll, b"VirtualAlloc2FromApp\0" as *const u8 as _) as VirtualAlloc2Ptr;
        FreeLibrary(hDll);
    }
    // Try to see if large OS pages are supported
    let err: u32 = 0;
    let ok: bool = option_is_enabled(option_large_os_pages);
    if ok {
        // To use large pages on Windows, we first need access permission
        // Set "Lock pages in memory" permission in the group policy editor
        // <https://devblogs.microsoft.com/oldnewthing/20110128-00/?p=11643>
        let token: HANDLE = null_mut();
        ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) != 0;
        if ok {
            let tp: TOKEN_PRIVILEGES;
            ok = LookupPrivilegeValueA(null_mut(), b"SeLockMemoryPrivilege\0" as *const _ as _, &mut tp.Privileges[0].Luid) != 0;
            if ok {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                ok = AdjustTokenPrivileges(token, FALSE, &mut tp, 0, null_mut(), 0 as _) != 0;
                if ok {
                    err = GetLastError();
                    ok = err == ERROR_SUCCESS;
                    if ok {
                        large_os_page_size = GetLargePageMinimum();
                    }
                }
            }
            CloseHandle(token);
        }
        if !ok {
            if err == 0 { err = GetLastError(); }
            warn!("cannot enable large OS page support, error {}", err);
        }
    }
}

#[cfg(not(windows))]
fn os_init() {
    // get the page size
    let result: i32 = sysconf(_SC_PAGESIZE);
    if (result > 0) {
        os_page_size = result as usize;
        os_alloc_granularity = os_page_size;
    }
    if (option_is_enabled(option_large_os_pages)) {
        large_os_page_size = (1u32 << 21); // 2MiB
    }
}

unsafe fn os_mem_free(addr: *mut u8, size: usize, stats: *mut Stats) -> bool {
    if addr.is_null() || size == 0 { return true; }
    let err: bool = false;
    #[cfg(windows)]
    {
        err = VirtualFree(addr as _, 0, MEM_RELEASE) == 0;
    }
    #[cfg(not(windows))]
    {
        err = munmap(addr, size) == -1;
    }
    _stat_decrease(&mut (*stats).committed, size as _); // TODO: what if never committed?
    _stat_decrease(&mut (*stats).reserved, size as _);
    if err {
        warn!("munmap failed: {}, addr {:08x}, size {}", errno::errno(), addr as usize, size);
        return false;
    } else {
        return true;
    }
}

#[cfg(windows)]
fn win_virtual_allocx(addr: *mut u8, size: usize, try_align: usize, flags: DWORD) -> *mut u8 {
    if try_align > 0 && (try_align % os_page_size()) == 0 && !pVirtualAlloc2.is_null() {
        // on modern Windows try use VirtualAlloc2
        let reqs: MEM_ADDRESS_REQUIREMENTS = Default::default();
        reqs.Alignment = try_align;
        let param: MEM_EXTENDED_PARAMETER = Default::default();
        param.Type = MEM_EXTENDED_PARAMETER_TYPE::MemExtendedParameterAddressRequirements;
        param.Pointer = &reqs;
        (pVirtualAlloc2)(addr as _, NULL, size as _, flags, PAGE_READWRITE, &param, 1) as _
    } else {
        VirtualAlloc(addr as _, size, flags, PAGE_READWRITE) as _
    }
}

fn win_virtual_alloc(addr: *mut u8, size: usize, try_align: usize, flags: DWORD) -> *mut u8 {
    let p = null_mut();
    if use_large_os_page(size, try_align) {
        p = win_virtual_allocx(addr, size, try_align, MEM_LARGE_PAGES | flags);
        // fall back to non-large page allocation on error (`p == NULL`).
    }
    if p.is_null() {
        p = win_virtual_allocx(addr, size, try_align, flags);
    }
    p
}

#[cfg(not(windows))]
fn unix_mmap(size: usize, try_align: usize, protect_flags: u32) -> *mut u8 {
    let p = null_mut();
    let flags = MAP_PRIVATE | MAP_ANONYMOUS;
    // TODO
    // #if defined(MAP_ALIGNED)  // BSD
    // if (try_alignment > 0) {
    //     size_t n = _mi_bsr(try_alignment);
    //     if (((size_t)1 << n) == try_alignment && n >= 12 && n <= 30) {  // alignment is a power of 2 and 4096 <= alignment <= 1GiB
    //         flags |= MAP_ALIGNED(n);
    //     }
    // }
    // #endif
    // #if defined(PROT_MAX)
    // protect_flags |= PROT_MAX(PROT_READ | PROT_WRITE); // BSD
    // #endif
    if (large_os_page_size > 0 && use_large_os_page(size, try_align)) {
        let lflags = flags;
        // TODO
        // #ifdef MAP_ALIGNED_SUPER
        // lflags |= MAP_ALIGNED_SUPER;
        // #endif
        // #ifdef MAP_HUGETLB
        // lflags |= MAP_HUGETLB;
        // #endif
        // #ifdef MAP_HUGE_2MB
        // lflags |= MAP_HUGE_2MB;
        // #endif
        if (lflags != flags) {
        // try large page allocation 
        // TODO: if always failing due to permissions or no huge pages, try to avoid repeatedly trying? 
        // Should we check this in _mi_os_init? (as on Windows)
        p = mmap(null_mut(), size, protect_flags, lflags, -1, 0);
        if p == MAP_FAILED { p = null_mut(); } // fall back to regular mmap if large is exhausted or no permission
        }
    }
    if p.is_null() {
        p = mmap(null_mut(), size, protect_flags, flags, -1, 0);
        if p == MAP_FAILED { p = null_mut(); }
    }
    p
}

// Primitive allocation from the OS.
// Note: the `alignment` is just a hint and the returned pointer is not guaranteed to be aligned.
fn os_mem_alloc(size: usize, try_align: usize, commit: bool, stats: *mut Stats) -> *mut u8 {
    debug_assert!(size > 0 && (size % os_page_size()) == 0);
    if size == 0 { return null_mut(); }

    let p: *mut u8 = null_mut();
    #[cfg(windows)]
    {
        let flags = MEM_RESERVE;
        if commit { flags |= MEM_COMMIT; }
        p = win_virtual_alloc(null_mut(), size, try_align, flags);
    } 
    #[cfg(not(windows))]
    {
        let protect_flags = if commit { PROT_WRITE | PROT_READ } else { PROT_NONE };
        p = unix_mmap(size, try_align, protect_flags);
    }
    _stat_increase(&mut (*stats).mmap_calls, 1);
    if !p.is_null() {
        _stat_increase(&mut (*stats).reserved, size as _);
        if commit { _stat_increase(&mut (*stats).committed, size as _); }
    }
    p
}

// Primitive aligned allocation from the OS.
// This function guarantees the allocated memory is aligned.
fn os_mem_alloc_aligned(size: usize, align: usize, commit: bool, stats: *mut Stats) -> *mut u8 {
    debug_assert!(align >= os_page_size() && ((align & (align - 1)) == 0));
    debug_assert!(size > 0 && (size % os_page_size()) == 0);
    if !(align >= os_page_size() && ((align & (align - 1)) == 0)) { return null_mut(); }
    size = align_up(size, os_page_size());
    
    // try first with a hint (this will be aligned directly on Win 10+ or BSD)
    let p = os_mem_alloc(size, align, commit, stats);
    if p.is_null() { return null_mut(); }

    // if not aligned, free it, overallocate, and unmap around it
    if p as usize % align != 0 {
        os_mem_free(p, size, stats);
        if size >= (usize::max_value() - align) { return null_mut(); } // overflow
        let over_size: usize = size + align;

        #[cfg(windows)]
        {
            // over-allocate and than re-allocate exactly at an aligned address in there.
            // this may fail due to threads allocating at the same time so we
            // retry this at most 3 times before giving up. 
            // (we can not decommit around the overallocation on Windows, because we can only
            //  free the original pointer, not one pointing inside the area)
            let flags = MEM_RESERVE;
            if commit { flags |= MEM_COMMIT; }
            for _ in 0..3 {
                // over-allocate to determine a virtual memory range
                p = os_mem_alloc(over_size, align, commit, stats);
                if p.is_null() { return null_mut(); } // error
                if p as usize % align == 0 {
                    // if p happens to be aligned, just decommit the left-over area
                    os_decommit((p as usize + size) as *mut u8, over_size - size, stats);
                    break;
                } else {
                    // otherwise free and allocate at an aligned address in there
                    os_mem_free(p, over_size, stats);
                    let aligned_p = align_up_ptr(p, align);
                    p = win_virtual_alloc(aligned_p, size, align, flags);
                    if p == aligned_p { break; } // success!
                    if !p.is_null() { // should not happen?
                        os_mem_free(p, size, stats);  
                        p = null_mut();
                    }
                }
            }
        }
        #[cfg(not(windows))]
        {
            // overallocate...
            p = os_mem_alloc(over_size, align, commit, stats);
            if p.is_null() { return null_mut(); }
            // and selectively unmap parts around the over-allocated area.
            let aligned_p = align_up_ptr(p, align);
            let pre_size: usize = aligned_p as usize - p as usize;
            let mid_size: usize = align_up(size, os_page_size());
            let post_size: usize = over_size - pre_size - mid_size;
            debug_assert!(pre_size < over_size && post_size < over_size && mid_size >= size);
            if pre_size > 0  { os_mem_free(p, pre_size, stats); }
            if post_size > 0 { os_mem_free((aligned_p as usize + mid_size) as *mut u8, post_size, stats); }
            // we can return the aligned pointer on `mmap` systems
            p = aligned_p;
        }
    }

    debug_assert!(p.is_null() || (!p.is_null() && (p as usize % align) == 0));
    p
}

pub unsafe fn _os_alloc(mut size: usize, stats: *mut Stats) -> *mut u8 {
  if size == 0 { return null_mut(); }
  size = os_good_alloc_size(size, 0);
  return os_mem_alloc(size, 0, true, stats);
}

pub unsafe fn _os_free(p: *mut u8, size: usize, stats: *mut Stats) {
  if size == 0 || p.is_null() { return; }
  size = os_good_alloc_size(size, 0);
  os_mem_free(p, size, stats);
}

pub unsafe fn _os_alloc_aligned(size: usize, align: usize, commit: bool, tld: *mut OsTld) -> *mut u8 {
  if size == 0 { return null_mut(); }
  size = os_good_alloc_size(size, align);
  align = align_up(align, os_page_size());
  return os_mem_alloc_aligned(size, align, commit, (*tld).stats);
}

/* -----------------------------------------------------------
  OS memory API: reset, commit, decommit, protect, unprotect.
----------------------------------------------------------- */


// OS page align within a given area, either conservative (pages inside the area only),
// or not (straddling pages outside the area is possible)
fn os_page_align_areax(conservative: bool, addr: *mut u8, size: usize, newsize: *mut usize) -> *mut u8 {
    assert!(!addr.is_null() && size > 0);
    if !newsize.is_null() { *newsize = 0; }
    if size == 0 || addr.is_null() { return null_mut(); }

    // page align conservatively within the range
    let start = if conservative {
        align_up_ptr(addr, os_page_size())
    } else {
        align_down_ptr(addr, os_page_size())
    } as usize;
    let end = if conservative {
        align_down(addr as usize + size, os_page_size())
    } else {
        align_up(addr as usize + size, os_page_size())
    };
    let diff: usize = end - start;
    if diff <= 0 {return null_mut();}

    debug_assert!(diff <= size);
    if !newsize.is_null() { *newsize = diff; }
    start as _
}

fn os_page_align_area_conservative(addr: *mut u8, size: usize, newsize: *mut usize) -> *mut u8 {
    os_page_align_areax(true, addr, size, newsize)
}

// Signal to the OS that the address range is no longer in use
// but may be used later again. This will release physical memory
// pages and reduce swapping while keeping the memory committed.
// We page align to a conservative area inside the range to reset.
fn os_reset(addr: *mut u8, size: usize, stats: *mut Stats) -> bool {
    // page align conservatively within the range
    let csize: usize = 0;
    let start: *mut u8 = os_page_align_area_conservative(addr, size, &mut csize);
    if csize == 0 { return true; }
    _stat_increase(&mut (*stats).reset, csize as _);

    #[cfg(windows)]
    {
        // Testing shows that for us (on `malloc-large`) MEM_RESET is 2x faster than DiscardVirtualMemory
        // (but this is for an access pattern that immediately reuses the memory)
        /*
        DWORD ok = DiscardVirtualMemory(start, csize);
        return (ok != 0);
        */
        let p: *mut u8 = VirtualAlloc(start as _, csize, MEM_RESET, PAGE_READWRITE) as _;
        assert!(p == start);
        if p != start { return false; }
        /*
        // VirtualUnlock removes the memory eagerly from the current working set (which MEM_RESET does lazily on demand)
        // TODO: put this behind an option?
        DWORD ok = VirtualUnlock(start, csize);
        if (ok != 0) return false;
        */
        true
    }
    #[cfg(not(windows))]
    {
        // #if defined(MADV_FREE)
        // static int advice = MADV_FREE;
        // int err = madvise(start, csize, advice);
        // if (err != 0 && errno == EINVAL && advice == MADV_FREE) {
        //     // if MADV_FREE is not supported, fall back to MADV_DONTNEED from now on
        //     advice = MADV_DONTNEED;
        //     err = madvise(start, csize, advice);
        // }
        // #else
        let err = madvise(start, csize, MADV_DONTNEED);
        // #endif
        if err != 0 {
            warn!("madvise reset error: start: {:p}, csize: {:08x}, errno: {}", start, csize, errno::errno().0);
        }
        //mi_assert(err == 0);
        err == 0
    }
}

// Protect a region in memory to be not accessible.
fn os_protectx(addr: *mut u8, size: usize, protect: bool) -> bool {
    // page align conservatively within the range
    let csize: usize = 0;
    let start: *mut u8 = os_page_align_area_conservative(addr, size, &mut csize);
    if csize == 0 { return false; }

    let err = 0;
    #[cfg(windows)]
    {
        let oldprotect = 0;
        let ok = VirtualProtect(start as _, csize, if protect { PAGE_NOACCESS } else { PAGE_READWRITE }, &mut oldprotect) != 0;
        err = if ok { 0 } else { GetLastError() };
    }
    #[cfg(not(windows))]
    {
        err = mprotect(start, csize, if protect { PROT_NONE } else { PROT_READ | PROT_WRITE });
    }
    if err != 0 {
        warn!("mprotect error: start: {:p}, csize: {:08x}, err: {}", start, csize, err);
    }
    err == 0
}

fn os_protect(addr: *mut u8, size: usize) -> bool {
    os_protectx(addr, size, true)
}

fn os_unprotect(addr: *mut u8, size: usize) -> bool {
    os_protectx(addr, size, false)
}

// Commit/Decommit memory. Commit is aligned liberal, while decommit is aligned conservative.
fn os_commitx(addr: *mut u8, size: usize, commit: bool, stats: *mut Stats) -> bool {
    // page align in the range, commit liberally, decommit conservative
    let csize: usize = 0;
    let start: *mut u8 = os_page_align_areax(!commit, addr, size, &mut csize);
    if csize == 0 { return true; }
    let err = 0;
    if commit {
        _stat_increase(&mut (*stats).committed, csize as _);
        _stat_increase(&mut (*stats).commit_calls, 1);
    } else {
        _stat_decrease(&mut (*stats).committed, csize as _);
    }

    #[cfg(windows)]
    {
        if commit {
            let p: *mut u8 = VirtualAlloc(start as _, csize, MEM_COMMIT, PAGE_READWRITE) as _;
            err = if p == start { 0 } else { GetLastError() };
        } else {
            let ok = VirtualFree(start as _, csize, MEM_DECOMMIT) != 0;
            err = if ok { 0 } else { GetLastError() };
        }
    }
    #[cfg(not(windows))]
    {
        err = mprotect(start, csize, if commit { PROT_READ | PROT_WRITE } else { PROT_NONE });
    }
    if err != 0 {
        warn!("commit/decommit error: start: {:p}, csize: {:08x}, err: {}", start, csize, err);
    }
    debug_assert!(err == 0);
    err == 0
}

fn os_commit(addr: *mut u8, size: usize, stats: *mut Stats) -> bool {
    os_commitx(addr, size, true, stats)
}

fn os_decommit(addr: *mut u8, size: usize, stats: *mut Stats) -> bool {
    os_commitx(addr, size, false, stats)
}

fn _mi_os_shrink(p: *mut u8, oldsize: usize, newsize: usize, stats: *mut Stats) -> bool {
    // page align conservatively within the range
    debug_assert!(oldsize > newsize && !p.is_null());
    if oldsize < newsize || p.is_null() { return false; }
    if oldsize == newsize { return true; }

    // oldsize and newsize should be page aligned or we cannot shrink precisely
    let addr: *mut u8 = (p as usize + newsize) as _;
    let size: usize = 0;
    let start: *mut u8 = os_page_align_area_conservative(addr, oldsize - newsize, &mut size);
    if size == 0 || start != addr { return false; }

    #[cfg(windows)]
    {
        // we cannot shrink on windows, but we can decommit
        os_decommit(start, size, stats)
    }
    #[cfg(not(windows))]
    {
        os_mem_free(start, size, stats)
    }
}
