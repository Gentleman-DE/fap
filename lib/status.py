import subprocess
import os
from termcolor import colored


def getDHCP():
    lease_file = "/var/lib/misc/dnsmasq.leases"
    if not os.path.exists(lease_file):
        print("No lease file found")
        return

    ret = os.popen(f"cat {lease_file}").read()
    lines = ret.strip().split('\n') if ret.strip() else []
    ipv4_leases = []
    ipv6_leases = []

    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        if ":" in parts[2] and not parts[2].startswith("*"):
            ipv6_leases.append(parts)
        else:
            ipv4_leases.append(parts)

    print("Connected devices\n")

    print("IPv4 Leases:")
    if ipv4_leases:
        for parts in ipv4_leases:
            print("Device: \t", parts[3] if len(parts) > 3 else "unknown")
            print("MAC-Adresse: \t", parts[1])
            print("IP-Adresse: \t", parts[2])
            print()
    else:
        print("No IPv4 devices\n")

    print("IPv6 Leases (DHCPv6):")
    if ipv6_leases:
        for parts in ipv6_leases:
            print("DUID: \t\t", parts[1])
            print("IPv6-Adresse: \t", parts[2])
            print("Hostname: \t", parts[3] if len(parts) > 3 else "unknown")
            print()
    else:
        print("No DHCPv6 devices\n")

    print("IPv6 Neighbors (SLAAC + DHCPv6):")
    neigh = os.popen("ip -6 neigh show dev wlan0").read()
    if neigh.strip():
        seen_macs = set()
        for line in neigh.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 4 and parts[1] == "lladdr":
                addr = parts[0]
                mac = parts[2]
                state = parts[3] if len(parts) > 3 else ""
                if addr.startswith("fe80::"):
                    continue
                key = f"{mac}_{addr}"
                if key not in seen_macs:
                    seen_macs.add(key)
                    print(f"MAC-Adresse: \t {mac}")
                    print(f"IPv6-Adresse: \t {addr}")
                    print(f"State: \t\t {state}")
                    print()
    else:
        print("No IPv6 neighbors found\n")


def getOVSStatus():
    os.system("ovs-vsctl show")
    os.system("ovs-vsctl list Mirror")


def getWlanStatus():
    process = subprocess.Popen(['cat', '/etc/hostapd.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    eingabe, err = process.communicate()
    eingabe = eingabe.decode('utf-8').split("\n")
    for line in eingabe:
        if line.startswith("ssid"):
            print(line)
        if line.startswith("wpa_passphrase"):
            print(line)


def getFWStatus():
    print("Results of ipset (IPv4):")
    os.system("ipset -L WL")
    print()
    print("Results of ipset (IPv6):")
    os.system("ipset -L WL6")


def getStatus():
    b = colored("-------------------------", "blue")
    print("Status der Umgebung:")
    print(b)
    print("WLAN:")
    getWlanStatus()
    print(b)
    print("OVS-Bridge")
    getOVSStatus()
    print(b)
    print("Access control:")
    getControl()
    print(b)
    print("Firewall")
    getFWStatus()
    print(b)
    getDHCP()
    print(b)
    print("DNS request")
    getDNSRequest()


def createStats(start, ende):
    print("---------------------")
    print("Some stats:")
    dauer = ende - start
    print("The capture process took approx.", dauer, "seconds")


def getDNSRequest():
    os.system("tshark -r /home/fap/pcap/test.pcap -T fields -e dns.qry.name -e dns.a")


def getControl():
    c = "WL"
    return c