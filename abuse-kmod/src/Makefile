KERNEL_SOURCE_VERSION ?= $(shell uname -r)
KERNEL_TREE ?= /lib/modules/$(KERNEL_SOURCE_VERSION)/build

obj-m := abuse.o

all:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_TREE) M=$(PWD) clean