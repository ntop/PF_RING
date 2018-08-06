#
# (C) 2009-15 - ntop.org
#

obj-m := pf_ring.o

# assigned by Makefile.dkms
GIT_REV:=

ifndef GIT_REV
 ifneq (, $(shell which git))
  ifneq (, $(shell git rev-parse --is-inside-work-tree 2> /dev/null | grep true))
   ifeq (, $(shell echo ${SUBDIRS}))
    GIT_BRANCH=$(shell git branch --no-color|cut -d ' ' -f 2)
    GIT_HASH=$(shell git rev-parse HEAD)
    ifneq ($(strip $(GIT_BRANCH)),)
     GIT_REV:=${GIT_BRANCH}:${GIT_HASH}
    endif
   endif
  endif
 endif
endif

ifneq ($(strip $(GIT_REV)),)
 GITDEF:=-DGIT_REV="\"${GIT_REV}\""
endif

ifeq (,$(BUILD_KERNEL))
 ifneq (,$(KERNELRELEASE))
  BUILD_KERNEL=$(KERNELRELEASE)
 else
  BUILD_KERNEL=$(shell uname -r)
 endif
endif

PWD := $(shell pwd)
EXTRA_CFLAGS += -I${PWD} ${GITDEF}

# Set no-pie for compilers that enable pie by default
test_no_nopie = $(shell echo "" | $(CC) -fsyntax-only -no-pie -xc - 2>&1 | grep unrecognized | wc -l)
ifneq (1,$(test_no_nopie))
  EXTRA_CFLAGS += -no-pie
endif
test_no_fnopie = $(shell echo "" | $(CC) -fsyntax-only -fno-pie -xc - 2>&1 | grep unrecognized | wc -l)
ifneq (1,$(test_no_fnopie))
  EXTRA_CFLAGS += -fno-pie
endif

HERE=${PWD}

# set the install path
INSTDIR := $(DESTDIR)/lib/modules/$(BUILD_KERNEL)/kernel/net/pf_ring
TARGETDIR := $(DESTDIR)/usr/src/$(BUILD_KERNEL)/include/linux/

all: Makefile pf_ring.c linux/pf_ring.h
#	@if test "$(USER)" = "root"; then \
#		echo "********** WARNING WARNING WARNING **********"; \
#		echo "*"; \
#		echo "* Compiling PF_RING as root might lead you to compile errors"; \
#		echo "* Please compile PF_RING as unpriviliged user"; \
#		echo "*"; \
#		echo "*********************************************"; \
#	fi
	make -C /lib/modules/$(BUILD_KERNEL)/build SUBDIRS=${HERE} EXTRA_CFLAGS='${EXTRA_CFLAGS}' modules

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
	mkdir -p $(DESTDIR)/usr/include/linux
	cp linux/pf_ring.h $(DESTDIR)/usr/include/linux
	@if test -d ${TARGETDIR}; then \
		cp linux/pf_ring.h ${TARGETDIR}; \
	fi
ifeq (,$(DESTDIR))
	/sbin/depmod $(BUILD_KERNEL)
else
	@echo "*****NOTE:";
	@echo "pf_ring,ko kernel module installed in ${DESTDIR}";
	@echo "/sbin/depmod not run.  modprobe pf_ring won't work " ;
	@echo "You can load the kernel module directly using" ;
	@echo "insmod <path>/pf_ring.ko" ;
	@echo "*****";
endif
