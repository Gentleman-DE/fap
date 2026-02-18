#!/bin/bash -x

# Dummy OVS      


modprobe dummy
ip link add dummy0 type dummy
ip link set name dummy0 dev dummy0

echo "Setze OVS-Settings"
ovs-vsctl --if-exists del-br br0 
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0
ip addr flush eth0
ip link set eth0 up
dhclient  -v br0
ovs-vsctl add-port br0 dummy0

echo "Mirror"
ovs-vsctl -- set Bridge br0  mirrors=@m -- --id=@eth0 get Port eth0 -- --id=@dummy0 get Port dummy0 -- --id=@m create Mirror name=mirror1 select-dst-port=@eth0 select-src-port=@eth0 output-port=@dummy0
ip link set dummy0 up
