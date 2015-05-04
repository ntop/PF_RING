Summary: PF_RING DNA dkms kernel drivers
Name: pfring-drivers-dna-dkms
Version: 1.1
Release: 0
License: GPL
Group: Networking/Utilities
URL: http://www.ntop.org/products/pf_ring/
Packager: Luca Deri <deri@ntop.org>
BuildArch: noarch
# Temporary location where the RPM will be built
Requires: e1000e-dna, igb-dna, ixgbe-dna
# 


%description
Virtual package for DNA drivers in DKMS format (http://www.ntop.org/pf_ring/).

%files
%defattr(-, root, root)

%post
 
%changelog
* Mon Sep 15 2014  <deri@centos.ntop.org> - 1.0.0
- Original upstream version


