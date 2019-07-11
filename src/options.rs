pub enum Options {
    option_large_os_pages
}
pub use Options::*;

pub fn option_is_enabled(_: Options) -> bool {
    unimplemented!()
}