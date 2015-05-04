modprobe kvm_intel
modprobe vhost_net

modprobe tun
modprobe bridge

brctl addbr br0
brctl addif br0 eth1
ifconfig br0 up

