Silicom/Fiberblaze Support
==========================

Prerequisites
-------------

Install the Fiberblaze package:

.. code-block:: console

   mkdir /opt/fiberblaze && tar xvzf fbcapture_<OS>_release_<version>.tar.gz -C /opt/fiberblaze

Load the driver:

.. code-block:: console

   echo 34359738368 > /proc/sys/kernel/shmmax
   echo 34359738368 > /proc/sys/kernel/shmall
   echo 2048 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
   export PATH=/opt/fiberblaze/bin:$PATH
   echo "/opt/fiberblaze/lib" > /etc/ld.so.conf.d/fiberblaze.conf; ldconfig
   cd /opt/fiberblaze/driver; make; ./load_driver.sh hugepages='2G'
   cd /opt/fiberblaze/bin; ./configurecard --device fbcard0 --configuration ../fbcard.cfg

Receive Traffic
---------------

The naming convention for RX is fbcard:CARD_ID:GROUP_NAME:GROUP_RING_ID where CARD_ID is the id of the card we want to open, GROUP_NAME is the name of the group specified in the configuration file fbcard.cfg used by configurecard, and RING_ID (in case of traffic hashing, i.e. Fiberblaze's RSS) if the id of the PRBs.

For example, if you have the following configuration in /opt/fiberblaze/fbcard.cfg:

.. code-block:: text

   prbGroup "b"
   {
       noPrbs 8
       hash HashPacket
       filter "hash"
   }

the device names are:

.. code-block:: text

   fbcard:0:b:0
   fbcard:0:b:1
   ...
   fbcard:0:b:7

Example receiving packets from card 0, group "b, ring 0: 

.. code-block:: console

   pfcount -i fbcard:0:b:0

If you want to open a single port instead of all oprts on a card, you can specify input = PORT_ID in the filter section:

.. code-block:: console

   prbGroup "a"
   {
       noPrbs 1
       filter "input = 0"
   }

Transmit Traffic
----------------

The naming convention for TX is fbcard:CARD_ID:PORT_ID. If you have a 4 port NIC, the PORT_ID will be 0 to 3.

Example (send packets from port 1 of cardId 0):

.. code-block:: console

   pfsend -i fbcard:0:1
