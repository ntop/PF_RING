all:
	cd kernel; make
	cd userland; make
	cd drivers; make

clean:
	cd kernel; make clean
	cd userland; make clean
	cd drivers; make clean
	-cd userland/snort/pfring-daq-module; make clean

snort:
	cd userland/snort/pfring-daq-module; autoreconf -ivf; ./configure; make
	cd userland/snort/pfring-daq-module-zc; autoreconf -ivf; ./configure; make

changelog:
	git log --since={`curl -s https://sourceforge.net/projects/ntop/files/PF_RING/|grep -o "<td headers=\"files_date_h\" class=\"opt\"><abbr title=\"[^\"]*\">[^<]*</abbr></td>"|head -n 3|tail -n 1|egrep -o "[0-9]+\-[0-9]+\-[0-9]+"|head -n 1`} --name-only --pretty=format:" - %s" > ./doc/Changelog.txt

documentation:
	cd doc/doxygen; doxygen Doxyfile

