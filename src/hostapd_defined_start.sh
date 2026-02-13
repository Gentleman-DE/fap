SSID=$1
KEY=$2
sudo systemctl stop hostapd
sudo killall hostapd 2>/dev/null

sudo rfkill unblock wlan
sudo ip link set wlan0 down
sudo ip link set wlan0 up
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo ip addr add 10.98.76.5/24 dev wlan0

sudo cp /home/fap/src/hostapd.conf /etc/hostapd.conf
echo "ssid=$SSID" | sudo tee -a /etc/hostapd.conf
echo "Trage passprase ein"
echo "wpa_passphrase=$KEY" | sudo tee -a /etc/hostapd.conf

