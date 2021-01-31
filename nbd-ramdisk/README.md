# Usage

## Server

```
$ ./nbd-ramdisk.bin
```

## Client:

### Kernel

```
# modprobe nbd
```

### Connect

```
# nbd-client localhost 10809 /dev/nbd0
```

- `-b4096` sets the logical/physical block size to 4096 (default 512)

### Disconnect

```
# nbd-client -d /dev/nbd0
```