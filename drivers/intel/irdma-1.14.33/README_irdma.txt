==============================================================================
irdma - Linux* RDMA Driver for the E800 Series and X722 Intel(R) Ethernet Controllers
==============================================================================

--------
Contents
--------
- Overview
- Prerequisites
- Supported OS List
- Building and Installation
- Confirm RDMA Functionality
- iWARP/RoCEv2 Selection
- iWARP Port Mapper (iwpmd)
- Flow Control Settings
- ECN Configuration
- DSCP Configuration
- Memory Requirements
- Resource Profile Limits
- Resource Limits Selector
- RDMA Statistics
- perftest
- MPI
- DMA Buf
- Performance
- Interoperability
- Dynamic Tracing
- Dynamic Debug
- Capturing RDMA Traffic with tcpdump
- Virtualization
- Link Aggregation
- Known Issues/Notes

--------
Overview
--------

The irdma Linux* driver enables RDMA functionality on RDMA-capable Intel
network devices. Devices supported by this driver:
   - Intel(R) Ethernet Controller E800 Series
   - Intel(R) Ethernet Network Connection X722

The Intel Ethernet 800 Series and X722 each support a different set of RDMA features.
    - Intel Ethernet 800 Series supports both iWARP and RoCEv2 RDMA transports, and also supports
      congestion management features like priority flow control (PFC) and
      explicit congestion notification (ECN).
    - X722 supports only iWARP and a more limited set of configuration
      parameters.

Differences between adapters are described in each section of this document.

For both Intel Ethernet 800 Series and X722, the corresponding LAN driver (ice or i40e) must be
built from source included in this release and installed on your system prior
to installing irdma.

-------------
Prerequisites
-------------

- Compile and install the Intel Ethernet 800 Series or X722 LAN PF driver from source included in
  this release. Refer to the ice or i40e driver README for installation
  instructions.
    * For Intel Ethernet 800 Series, use the ice driver.
    * For X722 adapters, use the i40e driver.
- For best results, use a fully supported OS from the Supported OS List below.
- For server memory requirements, see the "Memory Requirements" section of this
  document.
- Install required packages. Refer to the "Building" section of the rdma-core
  README for required packages for your OS:
        https://github.com/linux-rdma/rdma-core/blob/v51.0/README.md
    * RHEL 7 and SLES:
        Install all required packages listed in the rdma-core README.
    * RHEL 8:
        Install the required packages for RHEL 7, then install the following
        additional packages:
            dnf install python3-docutils perl-generators python3-Cython python3-devel
    * Ubuntu:
        Install the required packages listed in the rdma-core README, then
        install the following additional package:
            apt-get install python3-docutils libsystemd-dev

* Note:
The following are sample repo files that can be used to get the dependent packages
for rdma-core. However, these may not be all that is required.

- For SLES 15.2
    http://download.opensuse.org/distribution/leap/15.2/repo/oss

- For RHEL 8.1
    http://vault.centos.org/8.1.1911/PowerTools/x86_64/os/

-----------------
Supported OS List
-----------------

    Supported:
        * RHEL 9.4
        * RHEL 8.10
        * RHEL 8.9
        * SLES 15 SP6
        * SLES 15 SP5
        * SLES 15 SP4
        * Ubuntu 20.04.5 LTS Server(5.4 Kernel)
        * Ubuntu 22.04 LTS Server(5.15 Kernel)
        * Ubuntu 24.04 LTS Server(6.8 Kernel)
        * CentOS 7.4 with LTS 4.14
        * Debian 11

    Supported Not Validated:
        * RHEL 9.3
        * RHEL 9.2
        * RHEL 9.1
        * RHEL 9.0
        * RHEL 8.8
        * RHEL 8.7
        * RHEL 7.6 + OFED 4.17-1
        * RHEL 7.5 + OFED 4.17-1
        * RHEL 7.4 + OFED 4.17-1
        * RHEL 7.2 + OFED 4.8-2
        * SLES 15 SP3
        * SLES 15 SP2
        * SLES 15 SP1
        * SLES 12 SP5
        * SLES 15 + OFED 4.17-1
        * SLES 12 SP 4 + OFED 4.17-1
        * SLES 12 SP 3 + OFED 4.17-1
        * Ubuntu 18.04.0
        * Ubuntu 20.04.0
        * Linux kernel stable 6.8.*
        * Linux kernel longterm 6.6*, 6.1.*, 5.15.*, 5.10.*, 5.4.*, 4.19.*

-------------------------
Building and Installation
-------------------------

If using inbox drivers and libraries skip to step 6.

To build and install the irdma driver

1. Decompress the irdma driver archive:
        tar zxf irdma-<version>.tgz

2. Build and install the RDMA driver:
        cd irdma-<version>
        ./build.sh

   By default, the irdma driver is built using in-distro RDMA libraries and
   modules. Optionally, irdma may also be built using OFED modules. See the
   Supported OS List above for a list of OSes that support this option.
   * Note: Intel products are not validated on other vendors' proprietary
           software packages.
   To install irdma using OFED modules:
        - Download OFED-4.17-1.tgz from the OpenFabrics Alliance:
             wget http://openfabrics.org/downloads/OFED/ofed-4.17-1/OFED-4.17-1.tgz
        - Decompress the archive:
             tar xzvf OFED-4.17.1.tgz
        - Install OFED:
             cd OFED-4.17-1
             ./install --all
        - Reboot after installation is complete.
        - Build the irdma driver with the "ofed" option:
             cd /path/to/irdma-<version>
            ./build.sh ofed
        - Continue with the installation steps below.

3. Load the driver:
    RHEL and Ubuntu:
        modprobe irdma

    SLES:
        modprobe irdma --allow-unsupported

    Notes:
        - This modprobe step is required only during installation. Normally,
          irdma is autoloaded via a udev rule when ice or i40e is loaded:
             /usr/lib/udev/rules.d/90-rdma-hw-modules.rules
        - For SLES, to automatically allow loading unsupported modules, add the
          following to /etc/modprobe.d/10-unsupported-modules.conf:
              allow_unsupported_modules 1

The release now has convenience scripts to automate the build and install of rdma-core for
Red Hat, SLES, and Ubuntu distributions.

These scripts are:
* build_core.sh
* install_core.sh

For a system connected to the internet, this command (as root) will build and install the core:
	./build_core.sh -y && ./install_core.sh

The scripts are separate to allow for the migration of the build results to multiple servers.

The build results are stored in ~/rdma_core_build_<rev> where <rev> is the rdma_core revision from
above and can be rsync'ed to multiple hosts and installed via install_core.sh.

As an example <rev> for rdma-core-51.0.tar.gz would be 51.0.

The detailed usage is:

build_core.sh -h:
Usage: build_core.sh [-yl] [-e epelrpm] [-t coretar]

All downloads are opt-in, either by answering a yes/no question or providing the
-y override option.

The scripts download two items from the internet: the rdma-core tarball and the
epel RPM for rhel 9.

These downloads can be overridden via the -e and -t options with an absolute
path name for those items that have been pre-downloaded.

For an airgapped environment, the following RPMs must be provided, either by
copying the Red Hat and SLES repos or by creating a local repo.

The current build dependencies are:

SLES:

The output from this command will list the SLES rpms
rpmspec --parse suse/rdma-core.spec | grep BuildRequires | grep -v curl-mini

At this time, the list is:
    binutils
    cmake >= 2.8.11
    gcc
    make
    ninja
    pandoc
    perl
    pkgconfig
    pkgconfig(libnl-3.0)
    pkgconfig(libnl-route-3.0)
    pkgconfig(libsystemd)
    pkgconfig(libudev)
    pkgconfig(systemd)
    pkgconfig(udev)
    python3-base
    python3-Cython
    python3-devel
    python3-docutils
    systemd-rpm-macros
    valgrind-client-headers
    valgrind-devel

RHEL:

The output from this command will list the RHEL rpms
rpmspec --parse redhat/rdma-core.spec | grep BuildRequires

At this time, the list is:
    binutils
    cmake
    gcc
    libnl3-devel
    ninja-build
    pandoc
    perl-generators
    pkgconf-pkg-config
    python3-Cython
    python3-devel
    python3-docutils
    systemd
    systemd-devel
    valgrind-devel

UBUNTU:
The output from this command will list the UBUNTU debs
dpkg-checkbuilddeps 2>&1 | sed 's/([^)]*) *//g' | sed 's/dpkg-checkbuilddeps:\serror:\sUnmet build dependencies://g'

At this time, the list is:
    cmake
    cython3
    debhelper
    dh-systemd
    dh-python
    dpkg-dev
    libnl-3-dev
    libnl-route-3-dev
    libsystemd-dev
    libudev-dev
    ninja-build
    pandoc
    pkg-config
    python3-dev
    python3-docutils
    valgrind

The following RHEL RPMs are required to support the scripts themselves:

    dnf-plugins-core (dnf based)
    yum-utils (yum based)

To manually build the supporting rdma-core libraries follow steps 4 - 6:

4. Uninstall any previous versions of rdma-core user-space libraries.
   For example, in RHEL:
        yum erase rdma-core

        If yum erase doesn't work (on RHEL 8.4 it fails with "Error: The operation would result in removing the following protected packages: systemd"),
        use the following command to uninstall the rdma-core packages:

        rpm -e --nodeps ibacm iwpmd libibumad libibverbs librdmacm srp_daemon infiniband-diags 2>/dev/null
        rpm -e --nodeps rdma-core

        Note: The errors in post-uninstall scritps of these packages can be ignored with 2>/dev/null.
              The packages provided to rpm -e --nodeps above could be looked up with the following command: rpm -e rdma-core
              The output is "error: Failed dependencies: rdma-core(x86-64) =  is needed by (installed) rdma-core-devel
                                                         rdma-core(x86-64) =  is needed by (installed) iwpmd
                                                         rdma-core(x86-64) =  is needed by (installed) libibumad
                                                         rdma-core(x86-64) =  is needed by (installed) libibverbs
                                                         rdma-core(x86-64) =  is needed by (installed) ibacm
                                                         rdma-core(x86-64) =  is needed by (installed) librdmacm
                                                         rdma-core(x86-64) =  is needed by (installed) srp_daemon"

              To confirm that rdma-core is uninstalled after rpm -e --nodeps run: yum erase rdma-core
              The output should look like this: "No match for argument: rdma-core No packages marked for removal... Nothing to do. Complete!"


    Note: "yum erase rdma-core" will also remove any packages that depend on
          rdma-core, such as perftest or fio. Please re-install them after
          installing rdma-core.

          RHEL 9.0 does not have pandoc and ninja packages available through redhat repo.
          Temporary workaround is to bypass the issue for compiling rdma core by:
          sed -i s/"BuildRequires: pandoc"/"#BuildRequires: pandoc"/g  rdma-core.spec
          sed -i s/"%if 0%{?fedora} >= 33"/"%if 0%{?fedora} >= 33 || 0%{?rhel} >= 9"/g  rdma-core.spec

5. Patch, build, and install rdma-core user space libraries:

    RHEL:
        # Download rdma-core-51.0.tar.gz from GitHub
        wget https://github.com/linux-rdma/rdma-core/releases/download/v51.0/rdma-core-51.0.tar.gz
        # Apply patch libirdma-51.0.patch to rdma-core
        tar -xzvf rdma-core-51.0.tar.gz
        cd rdma-core-51.0
        patch -p2 < /path/to/irdma-<version>/libirdma-51.0.patch
        # Make sure directories rdma-core/redhat and contents are under group 'root'
        cd ..
        chgrp -R root rdma-core-51.0/redhat
        tar -zcvf rdma-core-51.0.tar.gz rdma-core-51.0
        # Build rdma-core
        mkdir -p ~/rpmbuild/SOURCES
        mkdir -p ~/rpmbuild/SPECS
        cp rdma-core-51.0.tar.gz ~/rpmbuild/SOURCES/
        cd ~/rpmbuild/SOURCES
        tar -xzvf rdma-core-51.0.tar.gz
        cp ~/rpmbuild/SOURCES/rdma-core-51.0/redhat/rdma-core.spec ~/rpmbuild/SPECS/
        cd ~/rpmbuild/SPECS/
        rpmbuild -ba rdma-core.spec
        # Install RPMs
        cd ~/rpmbuild/RPMS/x86_64
        yum install *51.0*.rpm

    SLES:
        # Download rdma-core-51.0.tar.gz from GitHub
        wget https://github.com/linux-rdma/rdma-core/releases/download/v51.0/rdma-core-51.0.tar.gz
        # Apply patch libirdma-51.0.patch to rdma-core
        tar -xzvf rdma-core-51.0.tar.gz
        cd rdma-core-51.0
        patch -p2 < /path/to/irdma-<version>/libirdma-51.0.patch
        cd ..
        # Zip the rdma-core directory into a tar.gz archive
        tar -zcvf rdma-core-51.0.tar.gz rdma-core-51.0
        # Create an empty placeholder baselibs.conf file
        touch /usr/src/packages/SOURCES/baselibs.conf
        # Build rdma-core
        cp rdma-core-51.0.tar.gz /usr/src/packages/SOURCES
        cp rdma-core-51.0/suse/rdma-core.spec /usr/src/packages/SPECS/
        cd /usr/src/packages/SPECS/
        rpmbuild -ba rdma-core.spec --without=curlmini
        cd /usr/src/packages/RPMS/x86_64
        rpm -ivh --force *51.0*.rpm

    Ubuntu:
        To create Debian packages from rdma-core:
        # Download rdma-core-51.0.tar.gz from GitHub
        wget https://github.com/linux-rdma/rdma-core/releases/download/v51.0/rdma-core-51.0.tar.gz
        # Apply patch libirdma-51.0.patch to rdma-core
        tar -xzvf rdma-core-51.0.tar.gz
        cd rdma-core-51.0
        patch -p2 < /path/to/irdma-<version>/libirdma-51.0.patch
        # Note: The following change to debian/ibverbs-providers.install may be needed:
	# "usr/lib/*/libmana.so*"  change to "usr/lib/*/libmana.so.*" 
        # Build rdma-core
        dh clean --with python3,systemd --builddirectory=build-deb
        dh build --with systemd --builddirectory=build-deb
	sudo dh binary --with systemd --builddirectory=build-deb
        # This creates .deb packages in the parent directory
        # To install the .deb packages
        sudo dpkg -i ../*.deb

6. Add the following to /etc/security/limits.conf:
        * soft memlock unlimited
        * hard memlock unlimited
        * soft nofile 1048000
        * hard nofile 1048000

   In addition, the files /etc/systemd/user.conf and /etc/systemd/system.conf may need to have the following line:
	DefaultLimitMEMLOCK=1073741824
   This will change the Max locked memory for all process to 1G.

   Restart the active session so new values will take effect.
   This avoids any limits on user mode applications as far as pinned memory and number of open files used.

    Note: A reboot may be needed if any RDMA applications were running during the rdma-core reinstall.

The release includes:
* Driver signed with Intel’s private key in precompiled kernel module form
* Complete source code for this driver
* Intel’s public key

The Intel public key allows you to authenticate the signed driver in secure boot mode.
To authenticate the signed driver, you must place Intel's public key in the UEFI Secure Boot key database.

If you decide to recompile the .ko module from the provided source files, the new .ko module will not be signed.
To use this .ko module in Secure Boot mode, you must:
- Sign it yourself with your own private key.
- Add your public key to the UEFI Secure Boot key database.

--------------------------
Confirm RDMA functionality
--------------------------

After successful installation, RDMA devices are listed in the output of
"ibv_devices". For example:
    # ibv_devices
    device                 node GUID
    ------              ----------------
    rdmap175s0f0        40a6b70b6f300000
    rdmap175s0f1        40a6b70b6f310000

Notes:
    - Device names may differ depending on OS or kernel.
    - Node GUID is different for the same device in iWARP vs. RoCEv2 mode.

Each RDMA device is associated with a network interface. The sysfs filesystem
can help show how these devices are related. For example:
    - To show RDMA devices associated with the "ens801f0" network interface:
         # ls /sys/class/net/ens801f0/device/infiniband/
         rdmap175s0f0
    - To show the network interface associated with the "rdmap175s0f0" RDMA
      device:
         # ls /sys/class/infiniband/rdmap175s0f0/device/net/
         ens801f0

Before running RDMA applications, ensure that all hosts have IP addresses
assigned to the network interface associated with the RDMA device. The RDMA
device uses the IP configuration from the corresponding network interface.
There is no additional configuration required for the RDMA device.

To confirm RDMA functionality, run rping:

    1) Start the rping server:
          rping -sdvVa [server IP address]

    2) Start the rping client:
          rping -cdvVa [server IP address] -C 10

    3) rping will run for 10 iterations (-C 10) and print data payloads on
       the console.

    Notes:
        - Confirm rping functionality both from each host to itself and between
          hosts. For example:
            * Run rping server and client both on Host A.
            * Run rping server and client both on Host B.
            * Run rping server on Host A and rping client on Host B.
            * Run rping server on Host B and rping client on Host A.
        - When connecting multiple rping clients to a persistent rping server,
          older kernels may experience a crash related to the handling of cm_id
          values in the kernel stack. With Intel Ethernet 800 Series, this problem typically appears
          in the system log as a kernel oops and stack trace pointing to
          irdma_accept. The issue has been fixed in kernels 5.4.61 and later.
          For patch details, see:
          https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/drivers/infiniband/core/ucma.c?h=v5.9-rc2&id=7c11910783a1ea17e88777552ef146cace607b3c

----------------------
iWARP/RoCEv2 Selection
----------------------

X722:
The X722 adapter supports only the iWARP transport.

Intel Ethernet 800 Series:
The Intel Ethernet 800 Series supports both iWARP and RoCEv2 transports. By default, the
irdma driver is loaded in iWARP mode. RoCEv2 may be selected globally
(for all ports) using the module parameter "roce_ena=1"

--- Global Selection
To automatically enable RoCEv2 mode for all ports when the irdma driver is
loaded, add the following line to /etc/modprobe.d/irdma.conf:
    options irdma roce_ena=1

The irdma driver may also be manually loaded with the "roce_ena=1" parameter
on the modprobe command line. To manually load all irdma ports in RoCEv2 mode:
  - If the irdma driver is currently loaded, first unload it:
        rmmod irdma
  - Reload the driver in RoCEv2 mode:
        modprobe irdma roce_ena=1

Alternatively, ports may be individually set to RoCEv2 mode using the module
parameter roce_port_cfg set as a binary bit field converted to a decimal number.
All other ports are configured for iWARP mode.
    Example 1 - to configure only port 0 in RoCE v2 mode (0001b -> 1):
        modprobe irdma roce_port_cfg=1
    Example 2 - to configure both port 0 and port 1 in RoCE v2 mode (0011b -> 3):
        modprobe irdma roce_port_cfg=3
    Example 3 - to configure only port 3 in RoCE v2 mode (1000b -> 8):
        modprobe irdma roce_port_cfg=8

Note: The roce_ena module parameter supersedes roce_port_cfg.

If the irdma driver is currently loaded, first unload it:
        rmmod irdma
Reload the driver with appropriate roce_ena value:
        modprobe irdma roce_ena=1

-------------------------
iWARP Port Mapper (iwpmd)
-------------------------
The iWARP port mapper service (iwpmd) coordinates with the host network stack
and manages TCP port space for iWARP applications.

iwpmd is automatically loaded when ice or i40e is loaded via udev rules in
/usr/lib/udev/rules.d/90-iwpmd.rules.

To verify iWARP port mapper status:
    systemctl status iwpmd

---------------------
Flow Control Settings
---------------------

X722:
The X722 supports only link-level flow control (LFC).

Intel Ethernet 800 Series:
The Intel Ethernet 800 Series supports both link-level flow control (LFC) and priority
flow control (PFC). Enabling flow control is strongly recommended when using
Intel Ethernet 800 Series in RoCEv2 mode.

--- Link Level Flow Control (LFC) (Intel Ethernet 800 Series and X722)

To enable link-level flow control on Intel Ethernet 800 Series or X722, use "ethtool -A".
For example, to enable LFC in both directions (rx and tx):
    ethtool -A <interface> rx on tx on

Confirm the setting with "ethtool -a":
    ethtool -a <interface>

Sample output:
    Pause parameters for interface:
    Autonegotiate: on
    RX: on
    TX: on
    RX negotiated:  on
    TX negotiated:  on

Full enablement of LFC requires the switch or link partner be configured for
rx and tx pause frames. Refer to switch vendor documentation for more details.

--- Priority Level Flow Control (PFC) (Intel Ethernet 800 Series only)

Priority flow control (PFC) is supported on Intel Ethernet 800 Series in both willing and
non-willing modes. Intel Ethernet 800 Series also has two Data Center Bridging (DCB) modes: software
and firmware. For more background on software and firmware modes, refer to the
Intel Ethernet 800 Series ice driver README.
- For PFC willing mode, software DCB is recommended.
- For PFC non-willing mode, software DCB must be used.

Notes: Intel Ethernet 800 Series supports a maximum of 4 traffic classes (TCs), one of which may
       have PFC enabled. In addition, iWARP mode requires a VLAN to be configured to fully enable PFC.


*** PFC willing mode

In willing mode, Intel Ethernet 800 Series is "willing" to accept DCB settings from its link
partner. DCB is configured on the link partner (typically a switch), and the
Intel Ethernet 800 Series will automatically discover and apply the DCB settings to its own port.
This simplifies DCB configuration in a larger cluster and eliminates the need
to independently configure DCB on both sides of the link.

To enable PFC in willing mode on Intel Ethernet 800 Series:
1. Use ethtool to disable firmware DCB.
   ethtool --set-priv-flags <interface> fw-lldp-agent off

To confirm settings, use following command:
    ethtool --show-priv-flags <interface>

Expected output:
    fw-lldp-agent     :off

2. Install OpenLLDP if not already installed:
         yum install lldpad

3. Start the Open LLDP daemon:
        lldpad -d

4. Disable CEE transmission:
        lldptool -Ti <interface> -V CEE-DCBX enableTx=no

5. Reset the DCBX mode to be 'auto' (start in IEEE DCBX mode) after the next lldpad restart:
        lldptool -Ti <interface> -V IEEE-DCBX mode=reset

6. Configure willing configuration for interface:
        lldptool -Ti <interface> -V ETS-CFG enableTx=yes willing=yes

7. Configure willing recommendation for interface:
        lldptool -Ti <interface> -V ETS-REC enableTx=yes

8. Configure willing PFC for interface:
        lldptool -Ti <interface> -V PFC willing=yes enableTx=yes

9. Terminate the first instance of lldpad that was started (e.g. from initrd):
        lldpad -k

10. Remove lldpad state records from shared memory:
        lldpad -s

11. Restart service lldpad:
        systemctl restart lldpad.service

12. Check CEE mode enableTx settings. Must be no:
        lldptool -ti <interface> -V CEE-DCBX -c

Expected output:
        enableTx=no

13. Check DCBX mode settings. Must be auto:
        lldptool -ti <interface> -V IEEE-DCBX -c

Expected output:
        mode=auto

Switch DCB and PFC configuration syntax varies by vendor. Consult your switch
manual for details. Sample Arista switch configuration commands:
-  Example: Enable PFC for priority 0 on switch port 21
     * Enter configuration mode for switch port 21:
         switch#configure
         switch(config)#interface ethernet 21/1
     * Turn PFC on:
         switch(config-if-Et21/1)#priority-flow-control mode on
     * Set priority 0 for "no-drop" (i.e., PFC enabled):
         switch(config-if-Et21/1)#priority-flow-control priority 0 no-drop
     * Verify switch port PFC configuration:
         switch(config-if-Et21/1)#show priority-flow-control
- Example: Enable DCBX on switch port 21
     * Enable DCBX in IEEE mode:
         switch(config-if-Et21/1)#dcbx mode ieee
     * Show DCBX settings (including neighbor port settings):
         switch(config-if-Et21/1)#show dcbx

*** PFC non-willing mode

In non-willing mode, DCB settings must be configured on both Intel Ethernet 800 Series and its link
partner. Non-willing mode is software-based. OpenLLDP (lldpad and lldptool) is
recommended.

To enable non-willing PFC on Intel Ethernet 800 Series:
  1. Disable firmware DCB. Firmware DCB is always willing. If enabled, it
     will override any software settings.
         ethtool --set-priv-flags <interface> fw-lldp-agent off
  2. Install OpenLLDP
         yum install lldpad
  3. Start the Open LLDP daemon:
        lldpad -d
  4. Verify functionality by showing current DCB settings on the NIC:
        lldptool -ti <ifname>
  5. Configure your desired DCB settings, including traffic classes,
     bandwidth allocations, and PFC.
     The following example enables PFC on priority 0, maps all priorities to
     traffic class (TC) 0, and allocates all bandwidth to TC0.
     This simple configuration is suitable for enabling PFC for all traffic,
     which may be useful for back-to-back benchmarking. Datacenters will
     typically use a more complex configuration to ensure quality-of-service
     (QoS).
     a. Enable PFC for priority 0:
           lldptool -Ti <interface> -V PFC willing=no enabled=0
     b. Map all priorities to TC0 and allocate all bandwidth to TC0:
           lldptool -Ti <interface> -V ETS-CFG willing=no \
           up2tc=0:0,1:0,2:0,3:0,4:0,5:0,6:0,7:0 \
           tsa=0:ets,1:strict,2:strict,3:strict,4:strict,5:strict,6:strict,7:strict \
           tcbw=100,0,0,0,0,0,0,0
  6. Verify output of "lldptool -ti <interface>":
        Chassis ID TLV
            MAC: 68:05:ca:a3:89:78
        Port ID TLV
            MAC: 68:05:ca:a3:89:78
        Time to Live TLV
            120
        IEEE 8021QAZ ETS Configuration TLV
            Willing: no
            CBS: not supported
            MAX_TCS: 8
            PRIO_MAP: 0:0 1:0 2:0 3:0 4:0 5:0 6:0 7:0
            TC Bandwidth: 100% 0% 0% 0% 0% 0% 0% 0%
            TSA_MAP: 0:ets 1:strict 2:strict 3:strict 4:strict 5:strict 6:strict 7:strict
        IEEE 8021QAZ PFC TLV
            Willing: no
            MACsec Bypass Capable: no
            PFC capable traffic classes: 8
            PFC enabled: 0
        End of LLDPDU LTV
  7. Configure the same settings on the link partner.

Full enablement of PFC requires the switch or link partner be configured for
PFC pause frames. Refer to switch vendor documentation for more details.

Additional notes and example:
	The 800 Series supports a maximum of four TCs, only one of which has PFC enabled.
	Traffic classes must be contiguous and must start at zero.
	ETS bandwidth allocations must total 100%.
	Multiple priorities can map to the same TC.
	Linux PFC defines eight TCs, but if you are steering traffic using ToS, there are only four priorities
	available: 0, 2, 4, and 6, which correspond with ToS 0, 8, 24, and 16 respectively.

The following example configures RDMA on Priority = 2 and TC = 2:
	Follow steps 1 - 5 for non-willing mode above. Then Configure DCB:
		a. Enable PFC for priority 2:
			lldptool -Ti <interface> -V PFC willing=no enabled=2
		b. Map all priorities to TC0, TC1 and TC2 and allocate all bandwidth to TC2:
			lldptool -Ti <interface> -V ETS-CFG willing=no up2tc=0:0,1:1,2:2,3:0,4:0,5:0,6:0,7:0 \
			tsa=0:ets,1:ets,2:ets,3:strict,4:strict,5:strict,6:strict,7:strict tcbw=0,0,100,0,0,0,0,0
		   Note: Even with 0 allocated BW on TC0 and TC1, traffic can still occur on those TC's.
		c. Verify settings:
			 lldptool -ti <interface>
				Chassis ID TLV
					MAC: 12:ce:dc:05:92:25
				Port ID TLV
					MAC: 12:ce:dc:05:92:25
				Time to Live TLV
					120
				IEEE 8021QAZ ETS Configuration TLV
					 Willing: no
					 CBS: not supported
					 MAX_TCS: 8
					 PRIO_MAP: 0:0 1:1 2:2 3:0 4:0 5:0 6:0 7:0
					 TC Bandwidth: 0% 0% 100% 0% 0% 0% 0% 0%
					 TSA_MAP: 0:ets 1:ets 2:ets 3:strict 4:strict 5:strict 6:strict 7:strict
				IEEE 8021QAZ PFC TLV
					 Willing: no
					 MACsec Bypass Capable: no
					 PFC capable traffic classes: 8
					 PFC enabled: 2
				End of LLDPDU TL
		d. Set the default TOS for all RoCEv2 traffic to 8 (which maps to priority 2):
			echo 8 > /sys/kernel/config/rdma_cm/rdma<interface>/ports/1/default_roce_tos 


--- Directing RDMA traffic to a traffic class

When using PFC, traffic may be directed to one or more traffic classes (TCs).
Because RDMA traffic bypasses the kernel, Linux traffic control methods like
tc or cgroups can't be used. Instead, set the Type of Service (ToS) field on
your application command line. ToS-to-priority mappings are hardcoded in Linux
as follows:
  ToS   Priority
  ---   --------
   0       0
   8       2
  24       4
  16       6
Priorities are then mapped to traffic classes using ETS using lldptool or switch
utilities.

Examples of setting ToS 16 in an application:
  ucmatose -t 16
  ib_write_bw -t 16

Alternatively, for RoCEv2, ToS may be set for all RoCEv2 traffic using
configfs. For example, to set ToS 16 on device rdma<interface>, port 1:
  mkdir /sys/kernel/config/rdma_cm/rdma<interface>
  echo 16 > /sys/kernel/config/rdma_cm/rdma<interface>/ports/1/default_roce_tos

In order to use other priorities(i.e. 1, 3, 5, 7), a VLAN is required to be setup using the
egress-qos-map option. For example to map all priority 0 as priority 3:
  ip link add link <ifname> name <vlan-ifname> type vlan id <vlan-id> egress-qos-map 0:3 1:0

-----------------
ECN Configuration
-----------------
X722:
Congestion control settings are not supported on X722.

Intel Ethernet 800 Series:
The Intel Ethernet 800 Series supports the following congestion control algorithms:
    - iWARP DCTCP
    - iWARP TCP New Reno plus ECN
    - iWARP TIMELY
    - RoCEv2 DCQCN
    - RoCEv2 DCTCP
    - RoCEv2 TIMELY

Congestion control settings are accessed through configfs. Additional DCQCN
tunings are available via module parameters.

--- Configuration in configfs

To access congestion control settings:

1. After driver load, change to the irdma configfs directory:
        cd /sys/kernel/config/irdma

2. Create a new directory for each RDMA device you want to configure.
   Note: Use "ibv_devices" for a list of RDMA devices.
   For example, to create configfs entries for the rdmap<interface> device:
        mkdir rdmap<interface>

3. List the new directory to get its dynamic congestion control knobs and
   values:
        cd rdmap<interface>
        for f in *; do echo -n "$f: "; cat "$f"; done;

    If the interface is in iWARP mode, the files have a "iw_" prefix:
        - iw_dctcp_enable
        - iw_ecn_enable
        - iw_timely_enable

    If the interface is in RoCEv2 mode, the files have a "roce_" prefix:
        - roce_dcqcn_enable
        - roce_dctcp_enable
        - roce_timely_enable

4. Enable or disable the desired algorithms.

   To enable an algorithm: echo 1 > <attribute>
   For example, to add ECN marker processing to the default TCP New Reno iWARP
   congestion control algorithm:
        echo 1 > /sys/kernel/config/irdma/rdmap<interface>/iw_ecn_enable

    To disable an algorithm: echo 0 > <attribute>
    For example:
        echo 0 > /sys/kernel/config/irdma/rdmap<interface>/iw_ecn_enable

    To read the current status: cat <attribute>

    Default values:
        iwarp_dctcp_en: off
        iwarp_timely_en: off
        iwarp_ecn_en: ON

        roce_timely_en: off
        roce_dctcp_en: off
        roce_dcqcn_en: off

5. Remove the configfs directory created above. Without removing these
   directories, the driver will not unload.
          rmdir /sys/kernel/config/irdma/rdmap<interface>

--- Advanced Congestion Control Knobs

NOTE: These module parameters cannot be used if using inbox drivers

Module parameters on Intel Ethernet 800 Series for RoCEv2 DCQCN tuning:
        dcqcn_enable
            Enables the DCQCN algorithm for RoCEv2.
            Note: "roce_ena" must also be set to "true".
        dcqcn_cc_cfg_valid
            Indicates that all DCQCN parameters are valid and should be updated
            in registers or QP context.
        dcqcn_min_dec_factor
            The minimum factor by which the current transmit rate can be
            changed when processing a CNP. Value is given as a percentage
            (1-100).
        dcqcn_min_rate
            The minimum value, in Mbits per second, for rate to limit.
        dcqcn_F
            The number of times to stay in each stage of bandwidth recovery.
        dcqcn_T
            The number of microseconds that should elapse before increasing the
            CWND in DCQCN mode.
        dcqcn_B
            The number of bytes to transmit before updating CWND in DCQCN mode.
        dcqcn_rai_factor
            The number of MSS to add to the congestion window in additive
            increase mode.
        dcqcn_hai_factor
            The number of MSS to add to the congestion window in hyperactive
            increase mode.
        dcqcn_rreduce_mperiod
            The minimum time between 2 consecutive rate reductions for a single
            flow. Rate reduction will occur only if a CNP is received during
            the relevant time interval.

------------------
DSCP Configuration
------------------
The ice driver supports setting DSCP-based Layer 3 Quality of Service (L3 QoS) in the PF driver.

The following is an example of how to map all RoCEv2 traffic to a DSCP/ToS:
1. Map a DSCP/ToS to a TC
  lldptool -T -i <ethX> -V APP app=<prio>,<sel>,<pid>
    where:
      <prio>: The TC assigned to the DSCP/ToS code point
      <sel>: 5 for DSCP to TC mapping
      <pid>: The DSCP/ToS code point
  For example, to map DSCP value 63 to traffic class 0:
    lldptool -T -i eth0 -V APP app=0,5,63
2. Set the default_roce_tos
  Since the ToS field is 8 bits and the DSCP field is only 6 bits, set the ToS value to
  4 X DSCP value(4 X 63 = 252):
  mkdir /sys/kernel/config/rdma_cm/rdma<interface>
  echo 252 > /sys/kernel/config/rdma_cm/rdma<interface>/ports/1/default_roce_tos

NOTE:
  L3 QoS mode is not available when FW-LLDP is enabled. You also cannot enable
  FW-LLDP if L3 QoS mode is active. Please see the "L3 QoS mode" section, in the ice README,
  for more details.

-------------------
Memory Requirements
-------------------
Default irdma initialization requires a minimum of ~210 MB (for Intel Ethernet 800 Series) or
~160 MB (for X722) of memory per port.

For servers where the amount of memory is constrained, you can decrease the
required memory by lowering the resources available to Intel Ethernet 800 Series or X722 by loading
the driver with the following resource profile setting:

    modprobe irdma resource_profile=2

To automatically apply the setting when the driver is loaded, add the following
to /etc/modprobe.d/irdma.conf:
    options irdma resource_profile=2

Note: This can have performance and scaling impacts as the number of queue
pairs and other RDMA resources are decreased in order to lower memory usage to
approximately 55 MB (for Intel Ethernet 800 Series) or 51 MB (for X722) per port.

-----------------------
Resource Profiles
-----------------------
Resource profiles determine how resources are allocated between PFs and VFs.
Please see the Virtualization section for more information on profiles.

In the default resource profile, the RDMA resources configured for each
adapter are as follows:

    Intel Ethernet 800 Series (2 ports):
        Queue Pairs: 4092
        Completion Queues: 8189
        Memory Regions: 4194302
    X722 (4 ports):
        Queue Pairs: 1020
        Completion Queues: 2045
        Memory Regions: 2097150

For resource profile 2, the configuration is:

    Intel Ethernet 800 Series (2 ports):
        Queue Pairs: 508
        Completion Queues: 1021
        Memory Regions: 524286

    X722 (4 ports):
        Queue Pairs: 252
        Completion Queues: 509
        Memory Regions: 524286

------------------------
Resource Limits Selector
------------------------
In addition to resource profile, you can further limit resources via the
"limits_sel" module parameter:

Intel Ethernet 800 Series:
    modprobe irdma limits_sel=<0-6>
X722:
    modprobe irdma gen1_limits_sel=<0-5>

To automatically apply this setting when the driver is loaded, add the
following to /etc/modprobe.d/irdma.conf:
    options irdma limits_sel=<value>

The values below apply to a 2-port Intel Ethernet 800 Series.
        0 - Minimum, up to 124 QPs
        1 - Up to 1020 QPs
        2 - Up to 2044 QPs
        3 - Default, up to 4092 QPs
        4 - Up to 16380 QPs
        5 - Up to 65532 QPs
        6 - Maximum, up to 131068 QPs

For X722, the resource limit selector defaults to a value of 1 and provides
2K QPs. A single X722 port supports a maximum of 32k QPs, and a 4-port X722
supports up to 8k QPs per port.

---------------
RDMA Statistics
---------------
RDMA protocol statistics for Intel Ethernet 800 Series or X722 are found in sysfs. To display all
counters and values:
    cd /sys/class/infiniband/rdmap<interface>/hw_counters;
    for f in *; do echo -n "$f: "; cat "$f"; done;

The following counters will increment when RDMA applications are transferring
data over the network in iWARP mode:
    - tcpInSegs
    - tcpOutSegs

Available counters:
    ip4InDiscards       IPv4 packets received and discarded.
    ip4InReasmRqd       IPv4 fragments received by Protocol Engine.
    ip4InMcastOctets    IPv4 multicast octets received.
    ip4InMcastPkts      IPv4 multicast packets received.
    ip4InOctets         IPv4 octets received.
    ip4InPkts           IPv4 packets received.
    ip4InTruncatedPkts  IPv4 packets received and truncated due to insufficient
                          buffering space in UDA RQ.
    ip4OutSegRqd        IPv4 fragments supplied by Protocol Engine to the lower
                          layers for transmission
    ip4OutMcastOctets   IPv4 multicast octets transmitted.
    ip4OutMcastPkts     IPv4 multicast packets transmitted.
    ip4OutNoRoutes      IPv4 datagrams discarded due to routing problem (no hit
                          in ARP table).
    ip4OutOctets        IPv4 octets supplied by the PE to the lower layers for
                           transmission.
    ip4OutPkts          IPv4 packets supplied by the PE to the lower layers for
                          transmission.
    ip6InDiscards       IPv6 packets received and discarded.
    ip6InReasmRqd       IPv6 fragments received by Protocol Engine.
    ip6InMcastOctets    IPv6 multicast octets received.
    ip6InMcastPkts      IPv6 multicast packets received.
    ip6InOctets         IPv6 octets received.
    ip6InPkts           IPv6 packets received.
    ip6InTruncatedPkts  IPv6 packets received and truncated due to insufficient
                          buffering space in UDA RQ.
    ip6OutSegRqd        IPv6 fragments received by Protocol Engine
    ip6OutMcastOctets   IPv6 multicast octets transmitted.
    ip6OutMcastPkts     IPv6 multicast packets transmitted.
    ip6OutNoRoutes      IPv6 datagrams discarded due to routing problem (no hit
                           in ARP table).
    ip6OutOctets        IPv6 octets supplied by the PE to the lower layers for
                           transmission.
    ip6OutPkts          IPv6 packets supplied by the PE to the lower layers for
                           transmission.
    iwInRdmaReads       RDMAP total RDMA read request messages received.
    iwInRdmaSends       RDMAP total RDMA send-type messages received.
    iwInRdmaWrites      RDMAP total RDMA write messages received.
    iwOutRdmaReads      RDMAP total RDMA read request messages sent.
    iwOutRdmaSends      RDMAP total RDMA send-type messages sent.
    iwOutRdmaWrites     RDMAP total RDMA write messages sent.
    iwRdmaBnd           RDMA verbs total bind operations carried out.
    iwRdmaInv           RDMA verbs total invalidate operations carried out.
    RxECNMrkd           Number of packets that have the ECN bits set to
                           indicate congestion
    cnpHandled          Number of Congestion Notification Packets that have
                           been handled by the reaction point.
    cnpIgnored          Number of Congestion Notification Packets that have
                           been ignored by the reaction point.
    rxVlanErrors        Ethernet received packets with incorrect VLAN_ID.
    tcpRetransSegs      Total number of TCP segments retransmitted.
    tcpInOptErrors      TCP segments received with unsupported TCP options or
                           TCP option length errors.
    tcpInProtoErrors    TCP segments received that are dropped by TRX due to
                           TCP protocol errors.
    tcpInSegs           TCP segments received.
    tcpOutSegs          TCP segments transmitted.
    cnpSent             Number of Congestion Notification Packets that have
                           been sent by the reaction point.
    RxUDP               UDP segments received without errors
    TxUDP               UDP segments transmitted without errors

--------
perftest
--------
The perftest package is a set of RDMA microbenchmarks designed to test
bandwidth and latency using RDMA verbs. The package is maintained upstream
here: https://github.com/linux-rdma/perftest

perftest-4.5-0.17 is recommended.

Earlier versions of perftest had known issues with iWARP that have since been
fixed. Versions 4.4-0.4 through 4.4-0.18 are therefore NOT recommended.

To run a basic ib_write_bw test:
    1. Start server
           ib_write_bw -R
    2. Start client:
           ib_write_bw -R <IP address of server>
    3. Benchmark will run to completion and print performance data on both
       client and server consoles.

Notes:
    - The "-R" option is required for iWARP and optional for RoCEv2.
    - Use "-d <device>" on the perftest command lines to use a specific RDMA
      device.
    - For ib_read_bw, use "-o 1" for testing with 3rd-party link partners.
    - For ib_send_lat and ib_write lat, use "-I 96" to limit inline data size
      to the supported value.
    - iWARP supports only RC connections.
      RoCEv2 supports RC and UD.
      Connection types XRC, UC, and DC are not supported.
    - Atomic operations are not supported on Intel Ethernet 800 Series or X722.

-----------
MPI Testing
-----------
--- Intel MPI
Intel MPI uses the OpenFabrics Interfaces (OFI) framework and libfabric user
space libraries to communicate with network hardware.

* Recommended Intel MPI versions:
    Single-rail: Intel MPI 2021.6
    Multi-rail:  Intel MPI 2021.6

  Note: Intel MPI 2019u4 is not recommended due to known incompatabilites with
        iWARP.

* Recommended libfabric version: libfabric-1.11.0 or the latest release

  The Intel MPI package includes a version of libfabric. This "internal"
  version is automatically installed along with Intel MPI and used by default.
  To use a different ("external") version of libfabric with Intel MPI:
      1. Download libfabric from https://github.com/ofiwg/libfabric.
      2. Build and install it according to the libfabric documentation.
      3. Configure Intel MPI to use a non-internal version of libfabric:
             export I_MPI_OFI_LIBRARY_INTERNAL=0
         or  source <installdir>/intel64/bin/mpivars.sh -ofi_internal=0
      4. Verify your libfabric version by using the I_MPI_DEBUG environment
         variable on the mpirun command line:
             -genv I_MPI_DEBUG=1
         The libfabric version will appear in the mpirun output.

* Sample command line for a 2-process pingpong test:

     mpirun -l -n 2 -ppn 1 -host myhost1,myhost2 -genv I_MPI_DEBUG=5 \
     -genv FI_VERBS_MR_CACHE_ENABLE=1 -genv FI_VERBS_IFACE=<interface> \
     -genv FI_OFI_RXM_USE_SRX=0 -genv FI_PROVIDER='verbs;ofi_rxm' \
     /path/to/IMB-MPI1 Pingpong

  Notes:
   - For RoCEv2 use FI_PROVIDER=psm3
   - Example is for libfabrics 1.8 or greater. For earlier versions, use
     "-genv FI_PROVIDER='verbs'"
   - SRQ is not supported, set FI_OFI_RXM_USE_SRX=0
   - For Intel MPI 2019u6, use "-genv MPIR_CVAR_CH4_OFI_ENABLE_DATA=0".
   - When using Intel MPI, it's recommended to enable only one interface on
     your networking device to avoid MPI application connectivity issues or
     hangs. This issue affects all Intel MPI transports, including TCP and
     RDMA. To avoid the issue, use "ifdown <interface>" or "ip link set down
     <interface>" to disable all network interfaces on your adapter except for
     the one used for MPI.

--- OpenMPI

* OpenMPI version 4.0.3 is recommended.
* iWARP is not supported after version 4.1.4.

-----------
Performance
-----------
RDMA performance may be optimized by adjusting system, application, or driver
settings.

- Flow control is required for best performance in RoCEv2 mode and is optional
  in iWARP mode. Both link-level flow control (LFC) and priority flow control
  (PFC) are supported, but PFC is recommended. See the "Flow Control Settings"
  section of this document for configuration details.

- For bandwidth applications, multiple queue pairs (QPs) are required for best
  performance. For example, in the perftest suite, use "-q 8" on the command
  line to run with 8 QP.

- For best results, configure your application to use CPUs on the same NUMA
  node as your adapter. For example:
    * To list CPUs local to your NIC:
        cat /sys/class/infiniband/<interface>/device/local_cpulist
    * To specify CPUs (e.g., 27-47) when running a perftest application:
        taskset -c 24-47 ib_write_bw <test options>
    * To specify CPUs when running an Intel MPI application:
        mpirun <options> -genv I_MPI_PIN_PROCESSOR_LIST=24-47 ./my_prog

- For some workloads, latency may be improved by enabling push_mode in the
  irdma driver.
    * Create the configfs directory for your RDMA device:
        mkdir /sys/kernel/config/irdma/rdmap<interface>
    * Enable push_mode:
        echo 1 > /sys/kernel/config/irdma/rdmap<interface>/push_mode
    * Remove the directory
        rmdir /sys/kernel/config/irdma/rdmap<interface>

- System and BIOS tunings may also improve performance. Settings vary by
  platform - consult your OS and BIOS documentation for details.
  In general:
    * Disable power-saving features such as P-states and C-states
    * Set BIOS CPU power policies to "Performance" or similar
    * Set BIOS CPU workload configuration to "I/O Sensitive" or similar
    * On RHEL 7.*/8.*, use the "latency-performance" tuning profile:
         tuned-adm profile latency-performance

----------------
DMA Buf
----------------

Download and install intel-i915-dkms by following the instructions in
https://dgpu-docs.intel.com/driver/installation.html

Modify file /etc/modprobe.d/i915.conf
  cat /etc/modprobe.d/i915.conf
  options i915 force_probe=* enable_guc=3 enable_rc6=0 prelim_override_p2p_dit=1

If the file doesn't exist, create one. Reboot the system after this change.

Install libfabric and fabtests. There is a modification required in libfabric
as described in the Note section.

Example:
	fi_xe_rdmabw -m device -p "verbs;ofi_rxm" -t write
	fi_xe_rdmabw -m host -p "verbs;ofi_rxm" -t write <ip>

Note:
To use DMA Buf with libfabric and irdma, the following change is required in
libfabric prov/verbs/src/verbs_info.c:

static bool vrb_hmem_supported(const char *dev_name)

{
        if (ofi_hmem_p2p_disabled())

                return false;

       */ Adding a check to allow devices to use hmem */
       if (vrb_gl_data.dmabuf_support)

              return true;


        return false;
}
 
For good performance (especially peer-to-peer PCIe READ performance) Intel GPU
with PVC is needed.

----------------
Interoperability
----------------

--- Mellanox

Intel Ethernet 800 Series and X722 support interop with Mellanox RoCEv2-capable adapters.

In tests like ib_send_bw, use -R option to select rdma_cm for connection
establishment. You can also use gid-index with -x option instead of -R:

Example:
    On Intel Ethernet 800 Series or X722:  ib_send_bw -F -n 5 -x 0
    On Mellanox           :  ib_send_bw -F -n 5 -x <gid-index for RoCEv2> <ip>

    ...where x specifies the gid index value for RoCEv2.

Look in /sys/class/infiniband/mlx5_0/ports/1/gid_attrs/types directory for
port 1.

Note: Using RDMA reads with Mellanox may result in poor performance if there is
      packet loss.

--- Chelsio

X722 supports interop with Chelsio iWARP devices.

Load Chelsio T4/T5 RDMA driver (iw_cxgb4) with parameter "dack_mode" set to 0.

    modprobe iw_cxgb4 dack_mode=0

To automatically apply this setting when the iw_cxgb4 driver is loaded, add the
following to /etc/modprobe.d/iw_cxgb4.conf:
    options iw_cxgb4 dack_mode=0


---------------
Dynamic Tracing
---------------
Dynamic tracing is available for irdma's connection manager.
Turn on tracing with the following command:
    echo 1 > /sys/kernel/debug/tracing/events/irdma_cm/enable

To retrieve the trace:
    cat /sys/kernel/debug/tracing/trace

-------------
Dynamic Debug
-------------
irdma support Linux dynamic debug.

To enable all dynamic debug messages upon irdma driver load, use the "dyndbg"
module parameter:
    modprobe irdma dyndbg='+p'

Debug messages will then appear in the system log or dmesg.

Enabling dynamic debug can be extremely verbose and is not recommended for
normal operation. For more info on dynamic debug, including tips on how to
refine the debug output, see:
   https://www.kernel.org/doc/html/v4.11/admin-guide/dynamic-debug-howto.html

-----------------------------------
Capturing RDMA Traffic with tcpdump
-----------------------------------
RDMA traffic bypasses the kernel and is not normally available to the Linux
tcpdump utility. You may capture RDMA traffic with tcpdump by using port
mirroring on a switch.

1. Connect 3 hosts to a switch:
   - 2 compute nodes to run RDMA traffic
   - 1 host to monitor traffic

2. Configure the switch to mirror traffic from one compute node's switch port
   to the monitoring host's switch port. Consult your switch documentation
   for syntax.

3. Unload the irdma driver on the monitoring host:
      # rmmod irdma
   Traffic may not be captured correctly if the irdma driver is loaded.

4. Start tcpdump on the monitoring host. For example:
      # tcpdump -nXX -i <interface>

5. Run RDMA traffic between the 2 compute nodes. RDMA packets will appear in
   tcpdump on the monitoring host.

-------------------
Virtualization
-------------------
The irdma driver supports virtualization on Intel Ethernet 800 Series only and requires
the iavf driver. Please refer to its README for installation instructions.

Loading the drivers:
Reload the irdma driver, on the host, with a VF specific resource_profile and
set the number of VFs needed.
The resource_profile value is one of the following:
  0 = PF only(default), no VF support, all resources assigned to PFs
  1 = Weighted VF, most resources assigned to the VFs, the PF gets minimal resources
  2 = Even Distribution, resources are distributed evenly among PFs and VFs

For example:
  modprobe -r irdma
  modprobe irdma resource_profile=2 max_rdma_vfs=2

Load the ice driver on the host and enable virtualization by setting the
number of VFs. For example, to set 2 VFs:
  echo 2 > /sys/class/net/p4p1/device/sriov_numvfs

Next, start the VM and make sure the iavf and irdma drivers are loaded. For example:
  modprobe iavf
  modprobe irdma

Notes:
 * The irdma driver must be loaded on the host when the VM is started. Otherwise,
   the iavf must be reloaded to enable RDMA functionality.
 * If the irdma driver on the host is unloaded, then any client VFs will require
   the iavf to be reloaded.
 * If LAG is active on an interface, SR-IOV VFs cannot be created on that interface.
 * Setting the sriov_numvfs on the host will load iavf driver on the host.

-------------------
Link Aggregation
-------------------
Link aggregation (LAG) and RDMA are compatible only if all the following are true:
- You are using an Intel Ethernet 800 Series device with the latest drivers and
NVM installed.
- RDMA technology is set to RoCEv2.
- LAG configuration is active-backup.
- Bonding is between two ports within the same device.
- The QoS configuration of the two ports matches prior to the bonding of the
devices.

If the above conditions are not met the ICE driver will disable RDMA.

NOTE: The first interface added to an aggregate (bond) is assigned as the
"primary" interface for RDMA and LAG functionality. If LAN interfaces are
assigned to the bond and you remove the primary interface from the bond, RDMA
will not function properly over the bonded interface. To address the issue,
remove all interfaces from the bond and add them again. Interfaces that are not
assigned to the bond will operate normally.

-------------------
Known Issues/Notes
-------------------

* Memory Windows are not supported.

* In iWARP mode, the establishment of a large number of connections may fail due
  to port collisions. This issue can occur if in-box rdma-core is used, because
  it doesn't enable the port mapper service (iwpmd).

* RHEL 8.7
Building irdma on RHEL 8.7 may fail due to issue in scripts/kernel-doc file.
To workaround this issue edit /usr/src/kernels/$(uname -r)/scripts/kernel-doc
Comment out the following line:
 #       $members =~ s/(?:__)?DECLARE_FLEX_ARRAY\s*\($args,\s*$args\)/$1 $2\[\]/gos;
Replace with:
        $members =~ s/(?:__)?DECLARE_FLEX_ARRAY\s*\(([^,)]+),\s*([^,)]+)\)/$1 $2\[\]/gos;

X722:
* Support for the Intel(R) Ethernet Connection X722 iWARP RDMA VF driver
(i40iwvf) has been discontinued.

* There may be incompatible drivers in the initramfs image. You can either
update the image or remove the drivers from initramfs.

Specifically, look for i40e, ib_addr, ib_cm, ib_core, ib_mad, ib_sa, ib_ucm,
ib_uverbs, iw_cm, rdma_cm, rdma_ucm in the output of the following command:
  lsinitrd |less
If you see any of those modules, rebuild initramfs with the following command
and include the name of the module in the "" list. For example:
  dracut --force --omit-drivers "i40e ib_addr ib_cm ib_core ib_mad ib_sa
  ib_ucm ib_uverbs iw_cm rdma_cm rdma_ucm"


Intel Ethernet 800 Series:
* Statistics may not be accurate for loopback operations.

* RDMA is not supported when Intel Ethernet 800 Series is configured for more than 4 ports.

* Intel Ethernet 800 Series is limited to 4 traffic classes (TCs), one of which may be enabled for
  priority flow control (PFC).

* When using RoCEv2 on Linux kernel version 5.9 or earlier, some iSER operations
may experience errors related to iSER's handling of work requests. To work
around this issue, set the Intel Ethernet 800 Series fragment_count_limit module parameter to 13.

* RoCEv2 devices require application level flow control in order to prevent message
loss due to insufficient receive buffers. The libfabric RxM provider implements application
level flow control for RDM endpoints running over RoCEv2 queue pairs.  The recommended way
to specify the provider in the RDM tests (e.g. fi_rdm) is with -p "ofi_rxm;verbs".

However, message endpoint tests (e.g. fi_msg_bw) which don't support the libfabric RxM
provider use the verbs provider with -p "verbs" directly and can fail without application
level flow control.

* iWARP and RoCEv2 do not interoperate. Configure Intel Ethernet 800 Series to use the same protocol(iWARP/
RoCEv2) as its connection partner.

X722 and Intel Ethernet 800 Series:
* Some commands (such as 'tc qdisc add' and 'ethtool -L') will cause the ice
driver to close the associated RDMA interface and reopen it. This will disrupt
RDMA traffic for a few seconds until the RDMA interface is available again.

* NOTE: Installing the ice driver, on RHEL, currently installs ice into initrd.
The implication is that the ice driver will be loaded on boot. The installation
process will also install any currently installed version of irdma into initrd.
This might result in an unintended version of irdma being installed. Depending
on your desired configuration and behavior of ice and irdma please look at the
following instructions to ensure the desired drivers are installed correctly.

    A. Desired that both ice and irdma are loaded on boot (default)
        1. Follow installation procedure for the ice driver
        2. Follow installation procedure for the irdma driver

    B. Desired that only ice driver is loaded on boot
        1. Untar ice driver
        2. Follow installation procedure for ice driver
        3. Untar irdma driver
        4. Follow installation procedure for irdma driver
        5. % dracut --force --omit-drivers "irdma"

    C. Desired that neither ice nor irdma is loaded on boot
        1. Perform all steps in B
        2. % dracut --force --omit-drivers "ice irdma"

* Note: Application use of fork()
If the RDMA application uses fork(), or any other function that generates a fork() call,
the application must call ibv_fork_init() before any RDMA resources are created. Failure
to do so may results in one or more of the following: data corruption, missed completions,
CQ overflows and SQ stalls.

-------
Support
-------
For general information, go to the Intel support website at:
http://www.intel.com/support/

If an issue is identified with the released source code on a supported kernel
with a supported adapter, email the specific information related to the issue
to linux.nics@intel.com

-------
License
-------
This software is available to you under a choice of one of two
licenses. You may choose to be licensed under the terms of the GNU
General Public License (GPL) Version 2, available from the file
COPYING in the main directory of this source tree, or the
OpenFabrics.org BSD license below:

  Redistribution and use in source and binary forms, with or
  without modification, are permitted provided that the following
  conditions are met:

  - Redistributions of source code must retain the above
    copyright notice, this list of conditions and the following
    disclaimer.

  - Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials
    provided with the distribution.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

----------
Trademarks
----------
Intel is a trademark or registered trademark of Intel Corporation
or its subsidiaries in the United States and/or other countries.

* Other names and brands may be claimed as the property of others
