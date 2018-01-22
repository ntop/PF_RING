Installing from GIT
===================

PF_RING can be downloaded in source format from GIT at https://github.com/ntop/PF_RING/
or installed from packages using Ubuntu/CentOS repositories at http://packages.ntop.org
as explained in README.apt_rpm_packages.

When you download PF_RING you fetch the following components:

* The PF_RING user-space SDK.
* An enhanced version of the libpcap library that transparently takes advantage of PF_RING if installed, or fallback to the standard behavior if not installed.
* The PF_RING kernel module.
* PF_RING ZC drivers.

Linux Kernel Module Installation
--------------------------------
In order to compile the PF_RING kernel module you need to have the linux kernel headers
(or kernel source) installed.

.. code-block:: console

   cd <PF_RING PATH>/kernel
   make
   make install


Note that the kernel module installation (via make install) requires root capabilities.
