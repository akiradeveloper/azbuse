doc:
	cargo doc --open --no-deps

.PHONY: abuse
abuse:
	cargo build --release --bin abuse-ramdisk
	cp target/release/abuse-ramdisk abuse-ramdisk.bin

.PHONY: nbd
nbd:
	cargo build --release --bin=nbd-ramdisk
	cp target/release/nbd-ramdisk nbd-ramdisk.bin