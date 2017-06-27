# Endace DAG support in PF_RING

## Prerequisite
DAG SDK installed.

PF_RING has native support for Endace DAG adapters, the DAG SDK needs to be 
installed in order to enable the DAG module at runtime.

## Installation
In order to get up and running with a DAG adapter just run the following commands.

Load the DAG module:

```
dagload
```

Compile/load pf_ring and sample applications:

```
cd PF_RING/kernel; make; sudo insmod pf_ring.ko
cd ../userland/lib; ./configure; make
cd ../libpcap; ./configure; make
cd ../examples; make
```

Run the sample application to make sure everything is working:

```
sudo ./pfcount -i dag:0
```

If you are installing from repository:

```
pfcount -i dag:0
```

Please note that in order to open port 0 from the DAG adapter you should 
specify "dag:0" as interface name, if you want to open stream 2 (default is 0)
on port 0 you should specify "dag:0@2".
