mod bindings {
    use crate::c_types;
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;