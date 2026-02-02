#!/bin/bash -x

# OVS korrekte Einstellungen setzen

echo "Setze OVS-Settings"
ovs-vsctl --if-exists del-br br0 
ovs-vsctl add-br br0
ovs-vsctl add-port br0 eth0
ip addr flush eth0
ip link set eth0 up
dhclient  -v br0
ovs-vsctl add-port br0 eth1

echo "Mirror"
ovs-vsctl -- set Bridge br0  mirrors=@m -- --id=@eth0 get Port eth0 -- --id=@eth1 get Port eth1 -- --id=@m create Mirror name=mirror1 select-dst-port=@eth0 select-src-port=@eth0 output-port=@eth1
ip link set eth1 up
