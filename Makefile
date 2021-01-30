doc:
	cargo doc --open --no-deps

abuse:
	cargo build --release --path=abuse-ramdisk
	cp target/release/abuse-ramdisk abuse-ramdisk-bin