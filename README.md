# userland-io

[![Crates.io](https://img.shields.io/crates/v/userland-io.svg)](https://crates.io/crates/userland-io)
[![documentation](https://docs.rs/userland-io/badge.svg)](https://docs.rs/userland-io)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/akiradeveloper/userland-io/blob/master/LICENSE)

## Motivation

Developing a virtual block device in Linux kernel is a hard task.
You must understand not only device-mapper framework but also the subsystems around it.
Writing a complicated code in C language will spend a ton of time and the
code output is usually hard to maintain. How do I know this? Because I've implemented [dm-writeboost](https://github.com/akiradeveloper/dm-writeboost).

When I met Rust language, soon I fell in love with the beautiful language and came to think of how it would be nice to write virtual block device in this language. With Rust, concurrent programming is not a difficult task while it is just like hell with C. Moreover, we can make use of sophisticated ecosystem and libraries from Rust community.

[fuse-rs](https://github.com/zargony/fuse-rs) is such a framework for filesystem layer but there nothing exists for block layer. That's why I started this project.

## Futurework

- I think it would be so nice to have a working transport in Windows and Mac.
- Stabilize abuse transport.
- A new target called dm-user is [proposed](https://www.redhat.com/archives/dm-devel/2020-December/msg00101.html) to upstream. dm-user is a DM target to proxy kernel bio to userland just like FUSE. This would bring better performance than with NBD because there is no TCP communication involved. If dm-user is merged, I will implement new transport in which IOs are coming from dm-user.