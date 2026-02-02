#!/bin/bash -x

# Dummy OVS


modprobe dummy
ip link add dummy0 type dummy
ip link set name dummy0 dev dummy0

echo "Setze OVS-Settings"

# Only create dummy bridge and dummy0, do not touch eth0
ovs-vsctl --if-exists del-br br0
ovs-vsctl add-br br0
ovs-vsctl add-port br0 dummy0
ip link set dummy0 up


# No mirroring or eth0 manipulation for single-NIC systems
