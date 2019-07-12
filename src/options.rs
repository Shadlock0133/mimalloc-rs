#[allow(non_camel_case_types)]
pub enum Options {
    option_page_reset,
    option_cache_reset,
    option_pool_commit,
    option_large_os_pages,
    option_secure,
    option_show_stats,
    option_show_errors,
    option_verbose,
}
pub use Options::*;

pub fn option_is_enabled(_: Options) -> bool {
    unimplemented!()
}

pub fn option_get(_: Options) -> u32 {
    unimplemented!()
}