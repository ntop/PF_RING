Capabilities
============

In order to run a raw capture with PF_RING, you need to run as privileged
user or set the proper capabilities to the application.

PF_RING used to check the CAP_SYS_ADMIN capability, however since kernel 3.8
the CAP_SYS_RAW capability is required.

Example on latest kernels: 

.. code-block:: console

   sudo setcap cap_net_raw+eip /usr/bin/pfcount

On kernel <3.8:

.. code-block:: console

   sudo setcap cap_net_admin+eip /usr/bin/pfcount

If you are using ZC drivers, CAP_IPC_LOCK and CAP_SYS_ADMIN are also required:

.. code-block:: console

   sudo setcap cap_net_raw,cap_ipc_lock,cap_sys_admin+eip /usr/bin/pfcount

Note: if your application is not capturing from a ZC interface directly (e.g.
it is capturing from a ZC queue created by zbalance_ipc), the CAP_SYS_ADMIN
capability is not required.

If you are running an application based on the PF_RING ZC API (e.g. zcount), hugepages 
permissions are also required. A common practice to create a group for hugepages
users and set the GID when mounting the hugetlb mountpoint:

.. code-block:: console

   mount -t hugetlbfs -o gid=1002 nodev /dev/hugepages

Please note that you can set the GID in the pf_ring hugepages configuration file
to automatically mount the hugetlb filesystem with the right permissions:

.. code-block:: console

   echo "node=0 hugepagenumber=1024 gid=1002" > /etc/pf_ring/hugepages.conf 

Please also note that the a ZC application using hugepages, needs to translate
virtual addresses to physical addresses. For this reason it needs to access
/proc/self/pagemap, however on some kernel versions (e.g. 4.0 and 4.1) opening
this file by unprivileged processes leads to failures with -EPERM for security 
reasons, while on other kernels the CAP_SYS_ADMIN capability is usually enough.

