obj-m := dummy_plugin.o

EXTRA_CFLAGS += -I$(PWD)/..
KBUILD_EXTRA_SYMBOLS := $(PWD)/../Module.symvers

all:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) clean
