# Wireshark Extcap

The extcap interface in Wireshark is a plugin-based mechanism to allow external 
executables to be used as traffic source in case the capture interface is not a 
standard network interface directly recognised by Wireshark.

The ntopdump extcap module under PF_RING/userland/wireshark/extcap can be used 
to open PF_RING interfaces (those that are not listed in ifconfig) or to extract 
traffic from a n2disk dumpset in Wireshark.

In order to get started with the ntopdump module, you need to compile the module:

``` 
make
``` 

and copy the module to the extcap path when Wireshark will look for extcap plugins,
in this example under /usr/lib/x86_64-linux-gnu/wireshark/extcap/ (if you install
from sources it will probably be /usr/local/lib/wireshark/extcap/)

``` 
cp ntopdump /usr/lib/x86_64-linux-gnu/wireshark/extcap/
``` 

You can read the extcap folder from the Wireshark menu:

"Help" -> "About Wireshark" -> "Folders" -> "Extcap path"

At this point you are ready to start Wireshark and start using the ntopdump module.

Once you start Wireshark, you will see two additional interfaces, "PF_RING interface"
and "n2disk timeline". Before running the capture, please configure the interface you
want to use by clicking on the gear icon of the corresponding interface.

