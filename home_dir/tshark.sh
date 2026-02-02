# Capture DNS traffic on wlan0 (Wi-Fi AP interface)
tshark -i wlan0 -w /home/fap/pcap/test.pcap -f "src port 53" -l -T fields -e dns.a -E occurrence=f >> ips
