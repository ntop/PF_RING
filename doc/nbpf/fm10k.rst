Intel FM10K nBPF Support
========================

This module allows to set filtering rules directly on the NIC card using the BFP-like syntax supported by nBPF filters. 
As the filter expression complexity affects the ability for translation into specific rules for the NIC, we will define a set of constraints and allowed expressions.

Supported cards
---------------

- Silicom PE3100G2DQIR [chip Intel FM10000 (code-name Red Rock Canyon)]

Requirements
------------

This library is part of libpfring, in order to compile libpfring with Red Rock Canyon (RRC) filtering support you have to install the RDIF software and configure/make the PF_RING fm10k driver.

RDIF software
~~~~~~~~~~~~~

RDIF software provides a daemon (rdifd) and an rdif control tool (rdifctl). RIDF is available in package  "RRC_100G_1R1b" that is provided by Silicom, Inc.

To compile and install RDIF software in the system directory do:

.. code-block:: console

   cd RRC_100G_1R1b/Linux/Redirect/RD_RRC_Control
   tar xzvf rdif-*.tar.gz
   cp fm_platform_attributes.cfg rdif-*/driver/
   cd rdif-*/
   ./clean
   sudo ./install

The rdifd daemon doesn't run automatically. You either need to start
it manually or via the script `load_driver.sh` discussed in the
following section.

PF_RING fm10k driver
~~~~~~~~~~~~~~~~~~~~

The fm10k driver is open-source and distributed with PF_RING. To get,
compile, and install it do:

.. code-block:: console

   git clone https://www.github.com/ntop/PF_RING
   cd PF_RING
   make
   cd drivers/intel/fm10k/fm10k-0.20.1-zc/src/
   make
   sudo ./load_driver.sh 


`load_driver.sh` loads the fm10k driver, starts the rdif daemon, and
sets the NIC switch with a default configuration, ready to receive
nBPF filters.

The output of `load_driver.sh` tells also the names of the fm10k
interfaces detected.

.. code-block:: console

   sudo ./load_driver.sh
   [...]
   Configuring ens9
   [...]
   Configuring enp3s0
   [...]

Take note of these names as you will need them.

Example
-------

Tools `pfcount` and `pfsend` bundled with PF_RING are used to send
traffic and test an nBPF hardware filter on the FM10000 RRC.

Following are the steps to build the tools:

.. code-block:: console

   cd PF_RING/userland
   make
   cd examples

To carry on the following test we loop-connect the two interfaces of the NIC,
interfaces that are `ens9` and `enp3s0` on our system.

Let's say now that we want to send traffic at 30Gbps from interface
`ens9`, with the additional requirements that packet lenght is 1500
bytes, the source ip address is 192.168.0.1 and the destination ip
address is 192.168.0.2. The `pfsend` command that has to be executed
is the following

.. code-block:: console

   sudo ./pfsend -i zc:ens9 -r 30 -b 1 -l 1500 -S 192.168.0.1 -D 192.168.0.2
   [...]
   TX rate: [current 2'372'059.48 pps/28.92 Gbps][average 2'370'550.71 pps/28.90 Gbps][total 196'761'818.00 pkts]
   TX rate: [current 2'372'061.83 pps/28.92 Gbps][average 2'370'568.70 pps/28.90 Gbps][total 199'133'951.00 pkts]
   [...]

This will be our traffic generator. Let's move to the traffic capture
with nBPF hardware filters. To capture without filters open another
console and do

.. code-block:: console

   sudo ./pfcount -i zc:enp3s0
   [...]
   Actual Stats: [2'445'073 pkts rcvd][1'000.08 ms][2'444'874.96 pps][29.81 Gbps]
   Actual Stats: [2'443'444 pkts rcvd][1'000.06 ms][2'443'294.95 pps][29.79 Gbps]

A look at the process highlights that pfcount is consuming 34% of a
CPU.

.. code-block:: console

   ps aux | grep pfcount
   root     17465 34.2  0.0  92248  2988 pts/1    R+   10:45   0:58 ./pfcount -i zc:enp3s0

Let's now try to add a 'capture-all' filter to our `pfcount`.

.. code-block:: console

   sudo ./pfcount -i zc:enp3s0  -f "src host 192.168.0.1"

A look at the process highlighs a slight increase in the CPU load that,
however, is still above 30%

.. code-block:: console

   ps aux | grep pfcount
   root     18465 38.1  0.0  92248  2984 pts/1    S+   10:50   0:16  ./pfcount -i zc:enp3s0 -f src host 192.168.0.1

Now we can try and add a 'drop-all' filter to our `pfcount` by
changing the ip source address.

.. code-block:: console

   sudo ./pfcount -i zc:enp3s0  -f "src host 192.168.0.2"

This time, process CPU occupancy is less that  1% confirming that our
hardware filters are doing the heavy lifting thus leaving the CPU available for
other activities.

.. code-block:: console

   ps aux | grep pfcount
   root     18911  0.5  0.0  92248  3100 pts/1    S+   10:53   0:00  ./pfcount -i zc:enp3s0 -f src host 192.168.0.2

API
---

The API of nBPF module for Intel RRC includes the following functions:

-  `int nbpf_rdif_reset(int unit)`
   
   The nbpf_rdif_reset function set the nic card in MON2 mode.
   In MON2 mode every port of the switch is unlinked and no traffic pass between
   the ports.
   Input parameter:

     - "unit" -> intel NIC card indentifier [range from 0 to (MAX_INTEL_DEV - 1)]

   Return value:

     - 0 on failure
     - 1 on success 

   Suggestion: use this function just once (in initialize phase of the NIC card).

-  `nbpf_rdif_handle_t *nbpf_rdif_init(char *ifname)`
   
   The nbpf_rdif_init function initializes the switch in order to put the port
   in inline mode:
   port 1 with port 3 for interface 0
   port 2 with port 4 for interface 1
   Input parameter:

     - "ifname" -> Interface name (for example "eth0", "ens9"....)

   Return value:

     - NULL on failure
     - handle pointer on success. Please use the handle with "nbpf_rdif_set_filter"
       and "nbpf_rdif_destroy" functions.

-  `int nbpf_rdif_set_filter(nbpf_rdif_handle_t *handle, char *bpf)`
   
   If possible the nbpf_rdif_set_filter transforms the bpf filter in rules for the 
   switch. Not all the bpf filters can be set (please read README.md.
   Input parameter:

     - handle -> data structure that contains the bpf rdif data. This handle is returned from nbpf_rdif_init function.
     - bpf -> bpf filter

   Return value:

     - 0 on failure
     - 1 on success

-  `void nbpf_rdif_destroy(nbpf_rdif_handle_t *handle)`
   
   The nbpf_rdif_destroy function removes the dinamic memory of the handle 
   and deletes the rules on the switch for an interface (puts it in inline mode).
   Input parameter:

     - handle -> data structure that contains the bpf rdif data. This handle is returned from nbpf_rdif_init function. Before exiting, the function frees the dinamic memory.


Testing
-------

You can use some commands to get stats about the packets that match with the rule you have 
set on the switch. 
The Silicom PE3100G2DQIR has two interfaces and two rules groups are set the bpf filter (group 1
for the first one and group 2 for the second one).

Commands:

- `rdifctl query_list 1` return how many rules the bpf filter has set on the switch for group 1 (interface 1)
- `rdifctl query_list 2` return how many rules the bpf filter has set on the switch for group 2 (interface 2)
- `sudo rdifctl rule_stat 1 1` how many packets of group 1 match with the rule 1
- `sudo rdifctl rule_stat 1 2` how many packets of group 1 match with the rule 2
- ect

Tipically when a bpf filter is set you have two rule. For instance for "src host 10.0.0.1" bpf filter you have:

.. code-block:: text

  rule 1: permit traffic with src ip 10.0.0.1
  rule 2: deny all

