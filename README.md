![pfring][pfring_logo] ![ntop][ntop_logo]
# PF_RING™

[![Build Status](https://travis-ci.org/ntop/PF_RING.png?branch=dev)](https://travis-ci.org/ntop/PF_RING)

### Introduction

PF_RING™ is a Linux kernel module and user-space framework that allows
you to process packets at high-rates while providing you a consistent
API for packet processing applications.

### Who needs PF_RING™?
Basically everyone who has to handle many packets per second. The term ‘many’ changes according to the hardware you use for traffic analysis. It can range from 80k pkt/sec on a 1,2GHz ARM to 14M pkt/sec and above on a low-end 2,5GHz Xeon. PF_RING™ not only enables you to capture packets faster, it also captures packets more efficiently preserving CPU cycles.

### Details
For more information about PF_RING™, please visit [http://ntop.org](http://www.ntop.org/products/packet-capture/pf_ring/)

If you want to know about PF_RING™ internals or for the User’s Manual visit the ntop.org  [Documentation](http://www.ntop.org/support/documentation/documentation/) section.

## License
PF_RING™ kernel module and drivers are distributed under the GNU GPLv2 license, LGPLv2.1 for the user-space PF_RING library, and are available in source code format.

[pfring_logo]: http://www.ntop.org/wp-content/uploads/2015/05/pf_ring-logo-150x150.png
[ntop_logo]: https://camo.githubusercontent.com/58e2a1ecfff62d8ecc9d74633bd1013f26e06cba/687474703a2f2f7777772e6e746f702e6f72672f77702d636f6e74656e742f75706c6f6164732f323031352f30352f6e746f702e706e67
