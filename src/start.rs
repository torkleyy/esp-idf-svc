use crate::log::Logger;

static LOGGER: Logger = Logger;

/// When compiling a Rust binary crate (e.g. in Cargo-first builds) and NOT doing
/// any tricks like using #[no_main] or #[start], the Rust compiler will autogenerate
/// a C function with the signature as below which will be proxying
/// the real Rust main function of your binary crate
///
/// So to bridge this function with the real C "app_main()" entrypoint
/// that ESP-IDF expects it is enough to implement app_main() and call in it
/// the "main" C function autogenerated by the Rust compiler
///
/// See https://github.com/rust-lang/rust/issues/29633 for more information
#[cfg(feature = "binstart")]
extern "C" {
    fn main(p1: isize, p2: *const *const u8) -> isize;
}

/// When compiling a static Rust library crate (e.g. by using a PIO->Cargo or a CMake->Cargo) build,
/// there is no main function that the Rust compiler expects, nor autogeneration of a callable
/// wrapper around it.
///
/// In that case (and if the "libstart" feature is enabled), it is _us_ (not the Rust compiler)
/// expecting the user to define a rust "main" function and it is our code below which is explicitly
/// calling it from app_main(). If the user does not define a main() runction in Rust, there will
/// be a linkage error instead of the nice Rust syntax error for binary crates.
///
/// Another restriction of the "libmain" feature is that the Rust main function will always have one
/// fixed signature: "fn main() -> !" - as opposed to the flexibility of main() in binary crates
/// where it can have quite a few different returning types
#[cfg(feature = "libstart")]
extern "Rust" {
    fn main() -> !;
}

#[no_mangle]
pub extern "C" fn app_main() {
    log::set_logger(&LOGGER).map(|()| LOGGER.initialize()).unwrap();

    #[cfg(feature = "binstart")]
    {
        match unsafe {main(0, core::ptr::null())} {
            0 => log::error!("Unexpected program exit!\n(no error reported)"),
            n => log::error!("Unexpected program exit!\n{}", n)
        }

        log::warn!("Will restart now...");
        panic!();
    }

    #[cfg(feature = "libstart")]
    unsafe {main()}
}
