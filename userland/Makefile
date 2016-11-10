all: libpfring pcap ring_examples zc_examples extcap # tcpdump_build lib_c++

###################

libpfring:
	cd lib; ./configure; make

pcap:
	cd libpcap; ./configure --enable-ipv6 --enable-dbus=no --without-libnl --with-snf=no --disable-bluetooth --disable-canusb --with-dag=no; make

ring_examples:
	cd examples; make

zc_examples:
	cd examples_zc; make

lib_c++:
	cd c++; make

tcpdump_build:
	cd tcpdump; ./configure ; make

extcap: libpfring pcap
	cd wireshark/extcap; make

###################

clean: libpfring_clean pcap_clean ring_examples_clean zc_examples_clean lib_c++_clean tcpdump_clean nbpf_clean extcap_clean

libpfring_clean:
	cd lib; make clean

pcap_clean:
	if test -f libpcap/config.status; then cd libpcap; make clean; fi

ring_examples_clean:
	cd examples; make clean

zc_examples_clean:
	cd examples_zc; make clean

lib_c++_clean:
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
