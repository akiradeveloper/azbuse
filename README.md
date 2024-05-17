# userland-io

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/akiradeveloper/userland-io/blob/master/LICENSE)

## Motivation

Developing a kernel module is hard.
It's hard because you need to understand the kernel internal which is very complicated
therefore hard to understand.

You sometimes want to develop a storage driver, either filesystem or block device,
but implemention is very hard.
Besides, in-kernel implementation may not be the best choice for the realization of your idea when it wants libraries that are found only in userland.
For these reasons, it would be very nice if you can develop a storage driver in userland and language like Rust is the optimal language choice for this purpose
because it often involves system-level programming.

Filesystem in userspace (FUSE) is an well-established solution for this problem
and there are libraries in many languages including Rust.
However, it only supports filesystem and not block device.

Block device in userspace is a pursued by many developers and there are existing projects
that implement this. However, none of them are best for the following two reasons.

Firstly, most of them use Network Block Device (NBD) for interacting with the kernel.
Using NBD is not the best option for these two reasons: 1) It is not optimal in performance because it involves network stack and 2) It drops information about the request (e.g. request flags) because NBD rounds it up. The best starred project called [BUSE](https://github.com/acozzette/BUSE) is in this category.

Secondly, none of them allow users to implement block device application in Rust. All I found are in C or Go.

This project **azbuse** aims to be the best solution for block device in userspace
by implementing special kernel module for interacting with kernel and providing Rust library for implementing block device applications.

## Architecture

The diagram below illustrates the architecture of **azbuse**.

After loading the azbuse kernel module, you can see a /dev/azbusectl device.
You also need to install azbusectl command to add or remove block device.
`sudo azbusectl add 1` will create /dev/azbuse1 and this will be the interface for
I/O submission from clients.

All you need to do is to implement `StorageEngine` trait and you can connect your implementation to kernel to get I/O requests from /dev/azbuse1 through the in-kernel queue.
The kernel interactions are done through ioctl and kernel pages are mmaped for
efficient data transfer.

![スクリーンショット 2024-05-17 17 45 27](https://github.com/akiradeveloper/userland-io/assets/785824/0d9a003a-1e0e-443d-8963-619752f037f6)

## Goal "Everything in Rust."

Since I am a Rust enthusiast, I want to implement everything in Rust.

- [x] Implement block device in userspace in Rust.
- [ ] Implementing kernel module in Rust using [Rust for Linux](https://rust-for-linux.com/).