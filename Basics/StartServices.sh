# checks (temporary)
sudo lsof -i :53
nmcli radio
rfkill list

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

# Start hostapd in background and save its PID
sudo hostapd hostapd-test.conf &
HOSTAPD_PID=$!
# Wait a moment for hostapd to initialize
sleep 2
# Start tshark in background and save its PID
sudo tshark -i wlan0 -w /tmp/hostap_session.pcap &
TSHARK_PID=$!

# Trap Ctrl+C (SIGINT) and EXIT to kill background jobs
cleanup() {
	echo "Stopping hostapd and tshark..."
	sudo kill $HOSTAPD_PID 2>/dev/null
	sudo kill $TSHARK_PID 2>/dev/null
	wait $HOSTAPD_PID 2>/dev/null
	wait $TSHARK_PID 2>/dev/null
	# Make the pcap file accessible for the current user
	sudo chmod 644 /tmp/hostap_session.pcap 2>/dev/null
	# Copy the pcap file to the current directory if it exists
	if [ -f /tmp/hostap_session.pcap ]; then
		cp /tmp/hostap_session.pcap ./hostap_session.pcap
		echo "hostap_session.pcap copied to current directory."
	fi
	exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Wait for background jobs
wait $HOSTAPD_PID $TSHARK_PID