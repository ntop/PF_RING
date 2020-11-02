Using PF_RING with Docker
=========================

This guide shows how to run packet processing applications based on PF_RING or
PF_RING ZC inside Docker containers in a few simple steps.

For an overview about the Docker networking support and configuration please refer 
to the Docker documentation (https://docs.docker.com/v1.7/articles/networking/).

As first step build the Docker image using the Dockerfile below, in this example
based on Ubuntu 20.

.. code-block:: console

  sudo docker build -t ubuntu20 -f Dockerfile.ubuntu20 .

Please note the Dockerfile is running the needed steps for installing the ntop
repository, installing pfring, and setting the entrypoint script run.sh,
in order to let us run commands by running the Docker image from command 
line.

Dockerfile.ubuntu20

.. code-block:: console

   FROM ubuntu:20.04
   MAINTAINER ntop.org
   
   RUN apt-get update && \
     apt-get -y -q install wget lsb-release gnupg && \
     wget -q http://apt.ntop.org/20.04/all/apt-ntop.deb && \
     dpkg -i apt-ntop.deb && \
     apt-get clean all
   
   RUN apt-get update && \
     apt-get -y install pfring
   
   RUN echo '#!/bin/bash\nset -e\nexec "$@"' > /run.sh && \
     chmod +x /run.sh
   
   ENTRYPOINT ["/run.sh"]

At this point it is possible to test pf_ring using pfcount as sample application.

Please note that the pf_ring.ko kernel module must be loaded on the host machine,
and that we need to set the proper capabilities using "--cap-add" in order to work 
with pf_ring.

.. note::  The version of the pf_ring kernel module loaded on the host and the 
           pf_ring library/application version running in the container have to be the same.

.. code-block:: console

   sudo docker run ubuntu20 pfcount -i eth0

Note: since PF_RING 7.1 and kernel 3.8 "--cap-add net_admin" is no longer needed.
An application running inside a docker container is able to capture traffic from the
interfaces visible inside the container only. If you want to capture traffic from an 
interface in the host network namespace you should run docker with "--network=host".

.. code-block:: console

   sudo docker run --network=host ubuntu20 pfcount -i eth0

When working with PF_RING ZC, using for instance zbalance_ipc for forwarding traffic
to consumer applications running inside Docker containers by means of ZC queues, we
need to bind the hugetlb mountpoint inside the container using "-v" and set the
proper capabilities. In order to test this, run zbalance_ipc on the host:

.. code-block:: console

   sudo zbalance_ipc -i eth0 -n 1 -m 1 -c 99

And attach pfcount from the container as consumer to the cluster queue created by zbalance_ipc:

.. code-block:: console

   sudo docker run -v /dev/hugepages:/dev/hugepages --cap-add ipc_lock ubuntu20 pfcount -i zc:99@0

Instead, if we need to create a ZC cluster in the container, for instance in case we 
want to run zbalance_ipc itself, the application needs to translate virtual addresses 
to physical addresses for providing DMA buffers to the adapter. For this reason it needs 
to access /proc/self/pagemap, however, depending on the kernel version, opening this 
file is not allowed to unprivileged processes, leading to failures (-EPERM). Setting 
the SYS_ADMIN capability is usually enough on latest kernels to make it work.
