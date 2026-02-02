r=$(pwgen -A -0 8 1)

sudo systemctl stop hostapd 
sudo cp /home/fap/src/hostapd.conf /etc/hostapd.conf
sudo echo "ssid="$r | sudo /usr/bin/tee --append /etc/hostapd.conf
echo "Trage passprase ein"
sudo echo "wpa_passphrase="$r |sudo /usr/bin/tee --append  /etc/hostapd.conf


sudo hostapd -B /etc/hostapd.conf -dd -t -f /tmp/hostapd.log
