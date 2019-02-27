export C_INCLUDE_PATH := $(shell cd ../../../../kernel/linux; pwd)

all:
	cp ../../../../kernel/Module.symvers src/
	cd src; make

clean:
	cd src; make clean
