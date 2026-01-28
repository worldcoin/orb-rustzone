// https://github.com/OP-TEE/optee_os/blob/764994e40843a9d734bf7df504d0f038fbff7be9/lib/libutils/ext/include/trace_levels.h#L26-L31

#[repr(u8)]
#[expect(dead_code)]
pub enum TraceLevel {
    /// optee refers to it as "msg"
    Error = 0,
    /// optee refers to it as "error"
    Warn = 1,
    Info = 2,
    Debug = 3,
    /// optee refers to it as "flow"
    Trace = 4,
}

/// internal use only
#[doc(hidden)]
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {{
        if ::optee_utee::trace::Trace::get_level() >= $level as _ {
            ::optee_utee::trace_println!($($arg)*)
        }
    }};
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        log!($crate::trace::TraceLevel::Error, $($arg)*)
    }
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        log!($crate::trace::TraceLevel::Warn, $($arg)*)
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        log!($crate::trace::TraceLevel::Info, $($arg)*)
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        log!($crate::trace::TraceLevel::Debug, $($arg)*)
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        log!($crate::trace::TraceLevel::Trace, $($arg)*)
    };
}
