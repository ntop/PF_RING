all: libpfring pcap build_examples build_examples_zc build_examples_ft build_extcap 
# build_tcpdump build_c++

###################

lib/Makefile:
	./configure

config: lib/Makefile

libpfring: config
	cd lib; make

build_nbpf: config
	cd nbpf; make

libpcap/Makefile:
	cd libpcap; ./configure --enable-ipv6 --enable-dbus=no --without-libnl --with-snf=no --disable-bluetooth --disable-canusb --with-dag=no

pcap: libpfring libpcap/Makefile
	cd libpcap; make

build_examples: config
	cd examples; make

build_examples_zc: config
	cd examples_zc; make

build_examples_ft: config
	cd examples_ft; make

build_c++: libpfring
	cd c++; make

tcpdump/Makefile:
	cd tcpdump; ./configure

build_tcpdump: libpfring pcap tcpdump/Makefile
	cd tcpdump; make

build_extcap: libpfring pcap
	cd wireshark/extcap; make

###################

clean: libpfring_clean pcap_clean examples_clean examples_ft_clean examples_zc_clean c++_clean tcpdump_clean nbpf_clean extcap_clean

libpfring_clean:
	cd lib; make clean

pcap_clean:
	if test -f libpcap/config.status; then cd libpcap; make clean; fi

examples_clean:
	cd examples; make clean

examples_zc_clean:
	cd examples_zc; make clean

examples_ft_clean:
	cd examples_ft; make clean

c++_clean:
	cd c++; make clean

tcpdump_clean:
	if test -f tcpdump/config.status; then cd tcpdump; make clean; fi

nbpf_clean:
	cd nbpf; make clean

extcap_clean:
	cd wireshark/extcap; make clean

install: libpfring pcap examples examples_zc examples_ft
	cd lib; make install
	cd libpcap; make install
	cd examples; make install
	cd examples_zc; make install
