# status
import subprocess
import os
from termcolor import colored


# get dhcp information of dnsmasq
def getDHCP():
    print("Connected devices")
    p = subprocess.Popen(['cat', '/var/lib/misc/dnsmasq.leases'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    eingabe, err = p.communicate()
    eingabe = str(eingabe.decode('utf-8').split("\n"))
    data = eingabe.split(" ")
    if (len(data) > 6):
        print(colored("Warning!!! More than one device connected", 'red'))
        for i in range(1, len(data), 5):
            print("Device: \t", data[i + 2])
            print("MAC-Adresse:\t", data[i])
            print("IP-Adresse:\t", data[i + 1])
    elif (len(data) == 1):
        print("No device connected")
    else:
        print("Device: \t", data[3])
        print("MAC-Adresse:\t", data[1])
        print("IP-Adresse:\t", data[2])


# get information of open vswitch
def getOVSStatus():
    #print("Getting information of OVS")
    os.system("ovs-vsctl show")
    os.system("ovs-vsctl list Mirror")


# Start WLAN, get information
def getWlanStatus():
    process = subprocess.Popen(['cat', '/etc/hostapd.conf'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    eingabe, err = process.communicate()
    eingabe = eingabe.decode('utf-8').split("\n")
    for line in eingabe:
        if (line.find("ssid") == 0):
            print(line)
            if (line.find("wpa_passphrase") == 0):
                print(line)


# Return firewall information
def getFWStatus():
    print("Results of ipset:")
    os.system("ipset -L WL")


# Return the relevant params of the environment
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
    # Connected Devices
    getDHCP()
    print(b)
    print("DNS request")
    getDNSRequest()


# Create some statistics
def createStats(start, ende):
    print("---------------------")
    print("Some stats:")
    # Measuring of time based on timeit
    dauer = ende - start
    print("The capture process took approx.", dauer, "seconds")


# Return all dns-requests captured by the tshark process
def getDNSRequest():
    os.system("tshark -r /home/fap/pcap/test.pcap -T fields -e dns.qry.name -e dns.a")


# Define the used access control technique, whitelist or novelty detection (this is still beta!!!)
# So, only WL is allowed, which results in this awesome funtion
def getControl():
    c = "WL"
    return c

