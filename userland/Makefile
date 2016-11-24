all: libpfring pcap build_examples build_examples_zc build_extcap 
# build_tcpdump build_c++

###################

config:
	./configure

libpfring: config
	cd lib; make

build_nbpf: config
	cd nbpf; make

pcap: libpfring
	cd libpcap; ./configure --enable-ipv6 --enable-dbus=no --without-libnl --with-snf=no --disable-bluetooth --disable-canusb --with-dag=no; make

build_examples: config
	cd examples; make

build_examples_zc: config
	cd examples_zc; make

build_c++: libpfring
	cd c++; make

build_tcpdump: libpfring pcap
	cd tcpdump; ./configure; make

build_extcap: libpfring pcap
	cd wireshark/extcap; make

###################

clean: libpfring_clean pcap_clean examples_clean examples_zc_clean c++_clean tcpdump_clean nbpf_clean extcap_clean

libpfring_clean:
	cd lib; make clean

pcap_clean:
	if test -f libpcap/config.status; then cd libpcap; make clean; fi

examples_clean:
	cd examples; make clean

examples_zc_clean:
	cd examples_zc; make clean

c++_clean:
	cd c++; make clean

tcpdump_clean:
	if test -f tcpdump/config.status; then cd tcpdump; make clean; fi

nbpf_clean:
	cd nbpf; make clean

extcap_clean:
	cd wireshark/extcap; make clean

install: libpfring pcap
	cd lib; make install
	cd libpcap; make install
