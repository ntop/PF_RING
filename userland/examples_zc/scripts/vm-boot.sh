
/usr/local/kvm/bin/qemu-system-x86_64 \
-enable-kvm \
-cpu host \
-k en \
-drive file=ubuntu-amd64.img,if=virtio \
-boot c \
-m 512 \
-netdev type=tap,id=guest0,script=if-up.sh,vhost=on -device virtio-net-pci,netdev=guest0,mac=DE:AD:BE:EF:FE:EB  \
-vnc 0.0.0.0:0 \
-chardev socket,path=/tmp/qmp0,server,nowait,id=qmp0 \
-mon chardev=qmp0,mode=control \
$@

