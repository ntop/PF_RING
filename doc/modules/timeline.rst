n2disk Timeline Module
======================

This module can be used to seamlessly extract traffic from a n2disk timeline using the PF_RING API.
n2disk is a traffic recording application producing multiple PCAP files (a per-file limit in duration 
or size can be used to control the file size), an index per file, and a timeline for keeping all the 
files in chronological order. Thanks to this module it is possible to query the timeline for specific
packets belonging to the whole dump set in a given time interval, matching a specific BPF filter.

Requirements
------------

Install pfring and n2disk following the instruction at http://packages.ntop.org according to your 
linux distribution and load the PF_RING kernel module as explained in the `Installing from Packages <https://www.ntop.org/guides/pf_ring/get_started/packages_installation.html>`_ section.

.. code-block:: console

   systemctl start pf_ring

Creating a dump set with n2disk
-------------------------------

This module extracts traffic from a n2disk dump set consisting of PCAP files, index files, and a timeline.
In order to instruct n2disk to create on-the-fly indexes you should use the -I option. The -A \<path\> option
instead should be used to create a timeline in \<path\>.

Command line example:

.. code-block:: console

   n2disk -i eth1 -o /storage/n2disk/eth1 -I -A /storage/n2disk/eth1/timeline

For additional options please refer to the `n2disk Documentation <https://www.ntop.org/guides/n2disk/>`_.

Usage
-----

In order to tell PF_RING that you want to select the timeline module, you should use the "timeline:" prefix 
followed by the timeline path as interface name. In addition to this, it is mandatory to provide a BPF filter
containing at the beginning the time interval using "start" and "end" tokens, followed by the actual packet 
filter (a subset of the BPF syntax is supported, please refer to the n2disk documentation) as in the example
below:

.. code-block:: console

   pfcount -i timeline:/storage/n2disk/eth1/timeline -f "start 2016-09-22 8:40:53 and end 2016-09-22 10:43:54 and host 192.168.2.130"

A specific example `pftimeline <https://github.com/ntop/PF_RING/blob/dev/userland/examples/pftimeline.c>`_ is 
also available in the PF_RING `examples <https://github.com/ntop/PF_RING/blob/dev/userland/examples/>`_ folder. 
You can use pftimeline to extract traffic generating a PCAP file with the matching traffic, or to pipe
another application for processing the matching traffic directly. Example:

.. code-block:: console

   pftimeline -t /storage/n2disk/eth1/timeline -b "2018-07-21 8:40:53" -e "2018-07-21 10:43:54" -f "host 192.168.2.130" -o - | tshark -i -

Wireshark support
-----------------

One of the most common use cases for the timeline module is the Wireshark integration, in fact it is very 
convenient to run wireshark directly on a n2disk timeline, specifying a BPF filter for extracting a small
portion of the whole dump set, and starting the analysis task while the extraction is progressing.
In order to do this, you can use the extcap modules we provide for Wireshark as described at https://github.com/ntop/wireshark-ntop
