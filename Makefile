doc:
	cargo doc --open --no-deps

install:
	cargo install --path=abuse-ramdisk
	cp target/release/abuse-ramdisk abuse-ramdisk-bin