use clap::Parser;

#[derive(Parser)]
enum Opts {
    Add { idx: u16 },
    Remove { idx: u16 },
}

const AZBUSE_CTL_ADD: u16 = 0x4186;
const AZBUSE_CTL_REMOVE: u16 = 0x4187;

nix::ioctl_write_int_bad!(azbuse_add_device, AZBUSE_CTL_ADD);
nix::ioctl_write_int_bad!(azbuse_remove_device, AZBUSE_CTL_REMOVE);

fn main() {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;

    let opts = Opts::parse();

    let fd = open("/dev/azbusectl", OFlag::empty(), Mode::empty()).expect("couldn't open /dev/azbusectl");
    match opts {
        Opts::Add { idx } => unsafe {
            azbuse_add_device(fd, idx as i32).unwrap();
        },
        Opts::Remove { idx } => unsafe {
            abbuse_remove_device(fd, idx as i32).unwrap();
        },
    }
}
