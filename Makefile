doc:
	cargo doc --open --no-deps

install:
	cargo install --path=abuse-proto
	cp target/release/abuse-proto abuse-proto-bin