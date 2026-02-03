# checks (temporary)
sudo lsof -i :53
nmcli radio
rfkill list

# disable dnsmasq autostart
sudo systemctl disable dnsmasq
sudo systemctl disable unbound

# Stop services
sudo systemctl stop dnsmasq
sudo killall dnsmasq
sudo systemctl stop unbound

# Setup Interface
sudo nmcli radio wifi on

# (not sure if needed)
sudo ip link set wlan0 down
sudo ip addr flush dev wlan0
sudo ip link set wlan0 up
sudo ip addr add 10.10.0.1/24 dev wlan0

# Start Services
sudo dnsmasq --conf-file=dnsmasq.conf
sudo hostapd hostapd-test.conf