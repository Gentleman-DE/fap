#tshark -i wlan0 -f "udp port 53"  -l -T fields -e dns.a -E occurrence=f >> /home/pi/dst.txt
tshark -i br0 -w /home/fap/pcap/test.pcap -f "src port 53"  -l -T fields -e dns.a -E occurrence=f >> ips 
