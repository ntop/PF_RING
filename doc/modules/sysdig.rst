Sysdig Module
=============

Prerequisite
------------

Install the sysdig package ("sudo apt-get install sysdig sysdig dkms" on Ubuntu)
or download it from www.sysdig.org

Installation
------------

Nothing to do beside loading the sysdig kernel module ("sudo modprobe sysdig_probe")

Usage
-----

.. code-block:: console

   pfcount -i sysdig:

or in case you want to add a sysdig filter do:

.. code-block:: console

   pfcount -v 2 -i sysdig: -f "evt.type=open"

