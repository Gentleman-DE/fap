# Räumt den FAP auf

userdel -r -f fap
rm -rf /var/www/html/fap
rm -rf /var/www/html/munin
rm -rf /var/www/html/index.html
rm -r /etc/rc.local
ovs-vsctl clear Bridge br0 mirrors
ovs-vsctl del-br br0
ifconfig eth0 up
dhclient eth0
ifconfig eth0
/etc/init.d/unbound stop
apt remove -y unbound tshark ipset dnsmasq hostapd munin openvswitch-common python3-termcolor python3-netifaces
apt -y autoremove
#cd /home/fap
echo "nameserver 9.9.9.9" >> /etc/resolv.conf

echo "Alles aufgeräumt"