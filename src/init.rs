use crate::types::*;

// Empty page used to initialize the small free pages array
const page_empty: Page = unimplemented!();

// --------------------------------------------------------
// Statically allocate an empty heap as the initial
// thread local value for the default heap,
// and statically allocate the backing heap for the main
// thread so it can function without doing any allocation
// itself (as accessing a thread local for the first time
// may lead to allocation itself on some platforms)
// --------------------------------------------------------

const heap_empty: Heap = unimplemented!();

// thread-local
static mut heap_default: *mut Heap = &mut heap_empty as _;


static tld_main: Tld = unimplemented!();

static mut heap_main: Heap = unimplemented!();

static mut process_is_initialized: bool = false;  // set to `true` in `process_init`.

static mut stats_main: Stats = unimplemented!();


unsafe fn ptr_cookie(p: *const u8) -> usize {
  p as usize ^ heap_main.cookie
}

/* -----------------------------------------------------------
  Initialization and freeing of the thread local heaps
----------------------------------------------------------- */

struct ThreadData {
    heap: Heap,  // must come first due to cast in `heap_done`
    tld:  Tld,
}

// Initialize the thread local default heap, called from `thread_init`
unsafe fn heap_init() -> bool {
    if (heap_is_initialized(heap_default)) { return true; }
    if (is_main_thread()) {
        // the main heap is statically allocated
        heap_default = &heap_main;
        debug_assert!(heap_default->tld->heap_backing == heap_default);
    }
    else {
        // use `os_alloc` to allocate directly from the OS
        let td: *mut ThreadData = os_alloc(size_of::<ThreadData>(), &stats_main); // Todo: more efficient allocation?
        if (td == NULL) {
            error!("failed to allocate thread local heap memory");
            return false;
        }
        tld_t*  tld = &(*td).tld;
        heap_t* heap = &(*td).heap;
        memcpy(heap, &heap_empty, sizeof(*heap));
        (*heap).thread_id = thread_id();
        (*heap).random = random_init((*heap).thread_id);
        (*heap).cookie = (heap ^ heap_random(heap)) | 1;
        (*heap).tld = tld;
        memset(tld, 0, sizeof(*tld));
        (*tld).heap_backing = heap;
        (*tld).segments.stats = &(*tld).stats;
        (*tld).os.stats = &(*tld).stats;
        heap_default = heap;
    }
    return false;
}

// Free the thread local default heap (called from `thread_done`)
unsafe fn heap_done() -> bool {
    let heap: *mut Heap = heap_default;
    if (!heap_is_initialized(heap)) {return true;}

    // reset default heap
    heap_default = (is_main_thread() ? &heap_main : &heap_empty);

    // todo: delete all non-backing heaps?

    // switch to backing heap and free it
    heap = (*(*heap).tld).heap_backing;
    if (!heap_is_initialized(heap)) {return false;}

    // collect if not the main thread 
    if (heap != &heap_main) {
        heap_collect_abandon(heap);
    }

    // merge stats
    stats_done(&(*(*heap).tld).stats);

    // free if not the main thread
    if (heap != &heap_main) {
        os_free(heap, sizeof(thread_data_t), &stats_main);
    }
    else {
        heap_destroy_pages(heap);
        debug_assert!(heap->tld->heap_backing == &heap_main);
    }
    return false;
}



// --------------------------------------------------------
// Try to run `thread_done()` automatically so any memory
// owned by the thread but not yet released can be abandoned
// and re-owned by another thread.
//
// 1. windows dynamic library:
//     call from DllMain on DLL_THREAD_DETACH
// 2. windows static library:
//     use `FlsAlloc` to call a destructor when the thread is done
// 3. unix, pthreads:
//     use a pthread key to call a destructor when a pthread is done
//
// In the last two cases we also need to call `process_init`
// to set up the thread local keys.
// --------------------------------------------------------

fn is_main_thread() -> bool {
  return (heap_main.thread_id == 0 || heap_main.thread_id == thread_id());
}

// This is called from the `malloc_generic`
unsafe fn thread_init() {
  // ensure our process has started already
  process_init();

  // initialize the thread local default heap
  if (heap_init()) {return;}  // returns true if already initialized

  // don't further initialize for the main thread
  if (is_main_thread()) {return;}

  stat_increase(&get_default_heap()->tld->stats.threads, 1);

  #if (DEBUG>0) // not in release mode as that leads to crashes on Windows dynamic override
  verbose_message("thread init: 0x%zx\n", thread_id());
  #endif
}

void thread_done(void) attr_noexcept {
  // stats
  heap_t* heap = get_default_heap();
  if (!is_main_thread() && heap_is_initialized(heap))  {
    stat_decrease(&heap->tld->stats.threads, 1);
  }

  // abandon the thread local heap
  if (heap_done()) return; // returns true if already ran

  #if (DEBUG>0)
  if (!is_main_thread()) {
    verbose_message("thread done: 0x%zx\n", thread_id());
  }
  #endif
}


// --------------------------------------------------------
// Run functions on process init/done, and thread init/done
// --------------------------------------------------------

fn process_init() {
  // ensure we are called once
  if (process_is_initialized) {return;}
  // access heap_default before setting process_is_initialized to ensure
  // that the TLS slot is allocated without getting into recursion on macOS
  // when using dynamic linking with interpose.
  heap_t* h = heap_default;
  process_is_initialized = true;

  heap_main.thread_id = thread_id();
  verbose_message("process init: 0x%zx\n", heap_main.thread_id);
  uintptr_t random = random_init(heap_main.thread_id)  ^ (uintptr_t)h;
  #ifndef __APPLE__
  heap_main.cookie = (uintptr_t)&heap_main ^ random;
  #endif
  heap_main.random = random_shuffle(random);
  #if (DEBUG)
  verbose_message("debug level : %d\n", DEBUG);
  #endif
  atexit(&process_done);
  process_setup_auto_thread_done();
  stats_reset();
  os_init();
}

fn process_done() {
    // only shutdown if we were initialized
    if (!process_is_initialized) {return;}
    // ensure we are called once
    static mut process_done: bool = false;
    if (process_done) {return;}
    process_done = true;

    collect(true);
    if (option_is_enabled(option_show_stats) ||
        option_is_enabled(option_verbose)) {
        stats_print(NULL);
    }
    verbose_message("process done: 0x%zx\n", heap_main.thread_id);
}



#if defined(_WIN32) && defined(SHARED_LIB)
  // Windows DLL: easy to hook into process_init and thread_done
  #include <windows.h>

  __declspec(dllexport) BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    UNUSED(reserved);
    UNUSED(inst);
    if (reason==DLL_PROCESS_ATTACH) {
      process_init();
    }
    else if (reason==DLL_THREAD_DETACH) {
      thread_done();
    }
    return TRUE;
  }

#elif defined(__cplusplus)
  // C++: use static initialization to detect process start
  static bool process_init(void) {
    process_init();
    return (heap_main.thread_id != 0);
  }
  static bool initialized = process_init();

#elif defined(__GNUC__) || defined(__clang__)
  // GCC,Clang: use the constructor attribute
  static void __attribute__((constructor)) process_init(void) {
    process_init();
  }

#elif defined(_MSC_VER)
  // MSVC: use data section magic for static libraries
  // See <https://www.codeguru.com/cpp/misc/misc/applicationcontrol/article.php/c6945/Running-Code-Before-and-After-Main.htm>
  static int process_init(void) {
    process_init();
    return 0;
  }
  typedef int(*_crt_cb)(void);
  #ifdef _M_X64
    __pragma(comment(linker, "/include:" "msvc_initu"))
    #pragma section(".CRT$XIU", long, read)
  #else
    __pragma(comment(linker, "/include:" "_msvc_initu"))
  #endif
  #pragma data_seg(".CRT$XIU")
  _crt_cb msvc_initu[] = { &process_init };
  #pragma data_seg()

#else
#pragma message("define a way to call process_init/done on your platform")
#endif
