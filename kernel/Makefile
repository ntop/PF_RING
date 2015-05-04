#
# (C) 2009-15 - ntop.org
#

obj-m := pf_ring.o

ifneq (, $(shell which git))
 ifeq (, $(shell echo ${SUBDIRS}))
  GIT_BRANCH=$(shell git branch --no-color|cut -d ' ' -f 2)
  GIT_HASH=$(shell git rev-parse HEAD)
  GITDEF := -DGIT_REV="\"${GIT_BRANCH}:${GIT_HASH}\""
 endif
endif

ifeq (,$(BUILD_KERNEL))
BUILD_KERNEL=$(shell uname -r)
endif

PWD := $(shell pwd)
EXTRA_CFLAGS += -I${PWD} ${GITDEF}

HERE=${PWD}

# set the install path
INSTDIR := $(DESTDIR)/lib/modules/$(BUILD_KERNEL)/kernel/net/pf_ring
TARGETDIR := $(DESTDIR)/usr/src/$(BUILD_KERNEL)/include/linux/

all: Makefile pf_ring.c linux/pf_ring.h
	@if test "$(USER)" = "root"; then \
		echo "********** WARNING WARNING WARNING **********"; \
		echo "*"; \
		echo "* Compiling PF_RING as root might lead you to compile errors"; \
		echo "* Please compile PF_RING as unpriviliged user"; \
		echo "*"; \
		echo "*********************************************"; \
	fi
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=${HERE} EXTRA_CFLAGS='${EXTRA_CFLAGS}' modules
#	cd plugins; make

dkms-deb:
	sudo make -f Makefile.dkms deb

dkms-rpm:
	sudo make -f Makefile.dkms rpm

clean:
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=$(HERE) clean
	\rm -f *~ Module.symvers  Module.markers  modules.order *#

install:
	mkdir -p $(INSTDIR)
	cp *.ko $(INSTDIR)
	cp linux/pf_ring.h $(DESTDIR)/usr/include/linux
	@if test -d ${TARGETDIR}; then \
		cp linux/pf_ring.h ${TARGETDIR}; \
	fi
ifeq (,$(DESTDIR))
	/sbin/depmod $(BUILD_KERNEL)
endif
