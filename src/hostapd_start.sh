sudo cp /home/fap/src/hostapd.conf /etc/hostapd.conf
echo "ssid=bob" | sudo tee -a /etc/hostapd.conf
echo "Trage passprase ein"
echo "wpa_passphrase=12345678" | sudo tee -a /etc/hostapd.conf

sudo hostapd -B /etc/hostapd.conf -dd -t -f /tmp/hostapd.log
