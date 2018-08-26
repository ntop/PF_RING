nBPF
====

nBPF is a filtering engine/SDK supporting the BPF (Berkeley Packet Filter) syntax 
and can be used as alternative to the implementation that can be found in libpcap 
and inside the kernel.

This version implements a subset of the filtering expressions supported by the original 
BPF, and it is designed to be fast and small in size, with no external dependencies.

This library has been designed to be efficient, and easy to embed in applications 
(e.g. n2disk uses it to filter traffic). 

Currently it is used by selected PF_RING modules to convert BPF filtering expressions 
onto hardware filters supported by popular network adapters such as Napatech, Intel FM10K, 
and Exablaze.

Expressions
-----------

An expression consists of one or more primitives.
The filter expressions are built by using AND and OR.

* Protocol: tcp, udp, sctp
* Direction: src, dst, src or dst, src and dst
* Type: host, port, proto, portrange (not supported on most adapters)

Additional constraints for packet capture filters include:

* it is not possible to use more than 1-level nesting using parenthesis
* it is not possible to use the "or" operator inside parenthesis
* it is not possible to mix different operators (only 1-level "or" of "and" blocks is allowed)
* is not possible to combine different directions in the same block using   the "and" operator.
* the NOT operator is not always permitted, depending on the match engine in use (for instance it is not supported on most adapters when translating to hardware rules)

Filter Examples
~~~~~~~~~~~~~~~

Valid filters:

* dst host 192.168.0.1
* src port 3000
* ip dst host 192.168.0.1
* src host 192.168.0.1 or dst host 192.168.0.1
* src port 3000 and src host 10.0.0.1 and proto 17
* tcp src port (80 or 443)
* (host 192.168.0.1 and port 3000) or (src host 10.0.0.1 and proto 17)

Unsupported filters:

* src port 3000 and (src host 10.0.0.1 or src host 10.0.0.2)
