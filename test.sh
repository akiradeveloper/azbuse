apt update && apt install sudo

sudo apt-get -y install kmod
sudo apt-get -y install nbd-client

cargo run --bin ramdisk &
pid=$!

sudo modprobe nbd

sudo nbd-client localhost 10809 /dev/nbd0
sudo badblocks -vw /dev/nbd0

kill -9 $pid