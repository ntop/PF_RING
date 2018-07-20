#!/bin/sh

set -ev

mkdir -p /opt/pf_ring/.work || true
mkdir -p /opt/bin || true
rm -rf /opt/pf_ring/current || true
ln -fs /opt/pf_ring/$PF_RING_VERSION/$COREOS_VERSION /opt/pf_ring/current

cat <<EOF > /etc/systemd/system/pf_ring-update.service
[Unit]
After=docker.service
Requires=docker.service
Description=PF_RING Update Driver
[Service]
EnvironmentFile=/etc/os-release
TimeoutStartSec=0
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/usr/bin/docker pull ntop/coreos-pfring-driver:\${VERSION}-$PF_RING_VERSION
ExecStart=/usr/bin/docker run -v /:/rootfs --privileged ntop/coreos-pfring-driver:\${VERSION}-$PF_RING_VERSION
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/usr-lib64.mount
[Unit]
After=pf_ring-update.service
Requires=pf_ring-update.service
ConditionPathExists=/opt/pf_ring/.work
Description=PF_RING Kernel Modules
[Mount]
EnvironmentFile=/etc/os-release
Type=overlay
What=overlay
Where=/usr/lib64
Options=lowerdir=/usr/lib64,upperdir=/opt/pf_ring/$PF_RING_VERSION/\${VERSION}/lib64,workdir=/opt/pf_ring/.work
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/pf_ring-persistenced.service
[Unit]
After=pf_ring.service
Requires=pf_ring.service
Description=PF_RING Persistence Daemon
[Service]
Type=forking
ExecStart=/opt/bin/pf_ring-persistenced --user pf_ring-persistenced --persistence-mode --verbose
ExecStopPost=/bin/rm -rf /var/run/pf_ring-persistenced
[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/pf_ring.service
[Unit]
After=usr-lib64.mount
Requires=usr-lib64.mount
Description=PF_RING Load
[Service]
Type=oneshot
RemainAfterExit=yes
#ExecStart=/usr/sbin/ldconfig
ExecStart=/usr/sbin/depmod -a
ExecStart=/usr/sbin/modprobe pf_ring
[Install]
WantedBy=multi-user.target
EOF

useradd -c "PF_RING Persistence Daemon" --shell /sbin/nologin --home-dir / pf_ring-persistenced || true

systemctl daemon-reload
systemctl enable pf_ring-update
systemctl enable usr-lib64.mount
systemctl enable pf_ring
systemctl enable pf_ring-persistenced
