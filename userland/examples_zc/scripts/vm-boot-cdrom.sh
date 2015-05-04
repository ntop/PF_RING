
/usr/local/kvm/bin/qemu-system-x86_64 \
-k it \
-drive file=ubuntu-amd64.img,if=virtio \
-cdrom /root/ubuntu-12.04.2-server-amd64.iso \
-boot d \
-m 512 \
-netdev type=tap,id=guest0,script=if-up.sh,vhost=on -device virtio-net-pci,netdev=guest0,mac=DE:AD:BE:EF:FE:EC  \
-vnc 0.0.0.0:0 \
$@

