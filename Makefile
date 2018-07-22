all:
	cd kernel; make
	cd userland; make
	cd drivers; make

install:
	cd userland; make install

clean:
	-cd kernel; make clean
	-cd userland; make clean
	-cd drivers; make clean
	-cd userland/snort/pfring-daq-module; make clean

snort:
	cd userland/snort/pfring-daq-module; autoreconf -ivf; ./configure; make
	cd userland/snort/pfring-daq-module-zc; autoreconf -ivf; ./configure; make

changelog:
	git log --since={`curl -s https://github.com/ntop/PF_RING/releases | grep datetime | head -n1 | egrep -o "[0-9]+\-[0-9]+\-[0-9]+"`} --name-only --pretty=format:" - %s" > ./doc/Changelog.txt

documentation:
	cd doc/doxygen; doxygen Doxyfile
	cd doc; make html

