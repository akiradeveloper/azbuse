use clap::Parser;

#[derive(Parser)]
enum Opts {
    Add { idx: u16 },
    Remove { idx: u16 },
}

const ABUSE_CTL_ADD: u16 = 0x4186;
const ABUSE_CTL_REMOVE: u16 = 0x4187;

nix::ioctl_write_int_bad!(abctl_add_device, ABUSE_CTL_ADD);
nix::ioctl_write_int_bad!(abctl_remove_device, ABUSE_CTL_REMOVE);

fn main() {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;

    let opts = Opts::parse();
    
    let fd = open("/dev/abctl", OFlag::empty(), Mode::empty()).expect("couldn't open /dev/abctl");
    match opts {
        Opts::Add { idx } => unsafe {
            abctl_add_device(fd, idx as i32).unwrap();
        },
        Opts::Remove { idx } => unsafe {
            abctl_remove_device(fd, idx as i32).unwrap();
        },
    }
}
