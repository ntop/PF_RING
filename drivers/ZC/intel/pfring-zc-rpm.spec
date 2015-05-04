Summary: PF_RING DNA dkms kernel drivers
Name: pfring-drivers-zc-dkms
Version: 1.2
Release: 0
License: GPL
Group: Networking/Utilities
URL: http://www.ntop.org/products/pf_ring/
Packager: Luca Deri <deri@ntop.org>
BuildArch: noarch
# Temporary location where the RPM will be built
Requires: e1000e-zc, igb-zc, ixgbe-zc, i40e-zc
# 


%description
Virtual package for ZC drivers in DKMS format (http://www.ntop.org/pf_ring/).

%files
%defattr(-, root, root)

%post
 
%changelog
* Wed Apr 15 2015  <deri@centos.ntop.org> - 1.2.0
- Added i40e drivers
* Mon Sep 15 2014  <deri@centos.ntop.org> - 1.0.0
- Original upstream version


