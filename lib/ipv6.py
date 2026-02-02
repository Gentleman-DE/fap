# Provides function for ipv6 communication
import netifaces as ni
import requests
from termcolor import colored
import uuid 
import os

IPV6SERVER="2a01:488:67:1000:5bfa:565b:0:1"

UUID_FILE = "/home/fap/uuid.txt"

def testIPv6():
    v6available = checkLocalNetworkConfig()
    if v6available: 
        checkIPv6Connection()


# Create UUID for transfering to webserver (only for statistical reasons)
def generateUUID():
    UUID = uuid.uuid4()
    #print(UUID)
    with open(UUID_FILE,"w") as f:
        f.write(str(UUID))
    
# Return the UUID stored in UUID_FILE
def getUUID():
    with open(UUID_FILE,"r") as f:
        return(f.read())

# Check for valid address
def v6(addr):
    ip = "2003::a"
    if (checkIP(ip)):
        print(f"{ip} is a valid ipv6-address")

# Check if a local ipv6 (LLA, ULA or GUA) is available
def checkLocalNetworkConfig():
    try:
        ip = ni.ifaddresses('eth0')[ni.AF_INET6][0]['addr']
        print(f"{ip} of eth0, should be unset or LLA")
        ip = ni.ifaddresses('br0')[ni.AF_INET6][0]['addr']
        print(f"{ip} of br0, should be a GUA")
    except KeyError as ke:
        print(colored("NO working IPv6 connectivity", "red"))
        return False
    else:
        return True


# Check if communication to ipv6 host is possible
def checkIPv6Connection():
    #print("Warning, IPv6 checks only available if FAP is inactive...")
    print("Connection to IPv6-address ", IPV6SERVER)
    if not os.path.isfile(UUID_FILE):
        generateUUID()
    UUID = getUUID()
    r = requests.get("http://["+IPV6SERVER+"]/index.old?"+UUID)
    if r.status_code == 200:
        print(colored("IPv6 connection successful","green"))
        print(f"Connection established, submitted {UUID} as a parameter")
    else: 
        print(colored("No usable IPv6 connection available","red"))
    
    