# SSID=$1
# KEY=$2
# sudo systemctl stop hostapd 
# sudo cp /home/fap/src/hostapd.conf /etc/hostapd.conf
# sudo echo "ssid="$SSID | sudo /usr/bin/tee --append /etc/hostapd.conf
# echo "Trage passprase ein"
# sudo echo "wpa_passphrase="$KEY |sudo /usr/bin/tee --append  /etc/hostapd.conf


# sudo hostapd -B /etc/hostapd.conf -dd -t -f /tmp/hostapd.log

#!/bin/bash
SSID=$1
KEY=$2

sudo systemctl stop hostapd
sudo killall hostapd 2>/dev/null

sudo rfkill unblock wlan
sudo ip link set wlan0 down
sudo ip link set wlan0 up

sudo cp /home/fap/src/hostapd.conf /etc/hostapd.conf
echo "ssid=$SSID" | sudo tee -a /etc/hostapd.conf
echo "Trage passprase ein"
echo "wpa_passphrase=$KEY" | sudo tee -a /etc/hostapd.conf