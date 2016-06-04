#
# Makefile for both static and dynamic PF_RING user libraries
#
#

#
# Installation directory
#
INSTDIR   = ${DESTDIR}//usr/local

#
# Search directories
#
INCLUDE   = -I../../kernel -I../libpcap  

#
# PF_RING ZC
#
PF_RING_ZC_OBJS  = pfring_zc_dev_e1000.o pfring_zc_dev_e1000e.o pfring_zc_dev_ixgbe.o pfring_zc_dev_igb.o pfring_zc_dev_i40e.o pfring_zc_dev_rss.o pfring_zc_dev_sal.o pfring_mod_zc.o pfring_mod_zc_dev.o pfring_mod_zc_spsc.o pfring_zc_cluster.o pfring_zc_mm.o uio_lib.o hugetlb_lib.o numa_lib.o pfring_zc_kvm.o pfring_zc_kvm_utils.o silicom_ts_card.o pfring_zc_dev_fm10k.o 

#
# DAG
#
DAG_OBJS  = 

#
# NT
#
NT_OBJS  = pfring_mod_nt.o 

#
# Mellanox (MLX)
#
MLX_OBJS  = 

#
# Accolade
#
ACCOLADE_OBJS  = 

#
# Myricom
#
MYRICOM_OBJS  = 

#
# Invea-Tech
#
INVEATECH_OBJS  = 

#
# Object files
#
OBJS      = pfring.o pfring_mod.o pfring_utils.o pfring_mod_stack.o pfring_hw_filtering.o \
	    pfring_hw_timestamp.o pfring_mod_sysdig.o ${PF_RING_ZC_OBJS} ${DAG_OBJS} ${NT_OBJS} ${MLX_OBJS} ${ACCOLADE_OBJS} ${MYRICOM_OBJS} ${INVEATECH_OBJS}

#
# C compiler and flags
#
#
# CROSS_COMPILE=arm-mv5sft-linux-gnueabi-
#
CC        = ${CROSS_COMPILE}gcc
CFLAGS    =  -march=native -mtune=native  -Wall -fPIC ${INCLUDE} -D HAVE_PF_RING_ZC     -D ENABLE_BPF  -D ENABLE_HW_TIMESTAMP -D HAVE_NT  -O2 # -g
LDFLAGS   = -g -shared
SYSLIBS   = -lpthread  -lrt -lntapi -lntos   

# How to make an object file
%.o: %.c %.h Makefile
#	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

#
# Main targets
#
STATICLIB  = libpfring.a
DYNAMICLIB = libpfring.so
TARGETS    = ${STATICLIB} ${DYNAMICLIB}
RING_H     = ../../kernel/linux/pf_ring.h

all: ${TARGETS}

${STATICLIB}: Makefile extract_pfring_zc_lib extract_nt_lib  ${OBJS} pfring.h ${RING_H}
	@echo "=*= making library $@ =*="
	ar rs $@ ${OBJS}
	ranlib $@

${DYNAMICLIB}: ${OBJS} extract_pfring_zc_lib extract_nt_lib  pfring.h ${RING_H} Makefile
	@echo "=*= making library $@ =*="
	${CC} ${LDFLAGS} ${OBJS} ${SYSLIBS} -o $@

extract_pfring_zc_lib:
	ar x libs/libpfring_zc_x86_64_core-avx2.a

extract_myricom_lib:
	ar x libs/libpfring_myricom_x86_64_core-avx2.a

extract_nt_lib:
	ar x libs/libpfring_nt_x86_64_core-avx2.a

install: install-static install-shared

install-includes:
	mkdir -p ${INSTDIR}/include
	cp pfring.h pfring_mod_sysdig.h pfring_zc.h ${INSTDIR}/include/

install-static: ${STATICLIB} install-includes
	mkdir -p ${INSTDIR}/lib
	cp ${STATICLIB} ${INSTDIR}/lib/

install-shared:	${DYNAMICLIB} install-includes
	mkdir -p ${INSTDIR}/lib
	cp ${DYNAMICLIB} ${INSTDIR}/lib/
	@if test "$(USER)" = "root"; then \
		ldconfig; \
	fi

clean:
	@rm -f ${TARGETS} *.o *~
