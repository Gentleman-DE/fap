import os
import sys
import time
import argparse
import datetime
import re
import ipaddress
from termcolor import colored
from lib.servicelist import *
from shutil import copyfile
import timeit
import logging
import glob
from lib.ipv6 import *
from lib.status import *

VERSION = "0.8.8"
DATUM = "07.03.2024"
DATADIR = "/var/www/html/fap/messenger"
TEMPLATEDIR = "/home/fap/template"
HOMEDIR = "/home/fap/src/"
UNBOUND_CONF = "/etc/unbound/unbound.conf.d/whitelist.conf"


# Setup verbose logging with timestamped logfile in /home/fap/logs/[timestamp]
def setup_logging():
    log_dir = '/home/fap/logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f'{log_dir}/{timestamp}.log'
    logging.basicConfig(
        filename=log_file,
        filemode='w',
        format='%(asctime)s %(levelname)s %(message)s',
        level=logging.DEBUG
    )
    logging.info(f'Logging started in {log_file}')

setup_logging()


parser=argparse.ArgumentParser(description="FAP CLI", prog='fap.py', usage='%(prog)s [options]')
parser.add_argument("-m", "--multiple", help = "list multiple targets, IP as well as FQDN")
parser.add_argument("-t", "--target", help = "Target service, Use -i for a list")
parser.add_argument("-u", "--unique", help = "Limit traffic to ONE unique system or FQDN")
parser.add_argument("-o", "--output", help = "Create pcap-file in given directory")
parser.add_argument("-d", "--debug", help = "Print debug information", action="store_true")
parser.add_argument("-v", "--version", help = "Print information of FAP", action="store_true")
group =parser.add_mutually_exclusive_group()
group.add_argument("-i", "--info", help = "List available apps", action = "store_true")
group.add_argument("-s", "--status", help = "Display current status", action = "store_true")
group.add_argument("-w", "--wlan", help = "Restart WLAN-Session", action = "store_true")
group.add_argument("-n", "--nameservice", help = "Clear misconfigured Unbound-Nameservice", action = "store_true")
group.add_argument("-x", "--finish", help = "Create an unsecure environment for updating FAP", action = "store_true")
group.add_argument("-6", "--ipv6", help = "Check IPv6 configuration", action = "store_true")
group.add_argument("--set", help = "Define the SSID and Key for a known wifi-env")
args = parser.parse_args()



# Everything about packet capture
def start_tshark():
    print_delimiter()
    print(">> Starting tshark")
    logging.info("Starting tshark")
    print("Checking for fifo.sh")
    logging.info("Checking for fifo.sh")
    fifo_id = find_pid("fifo.sh")
    if len(fifo_id) == 0:
        print("Fifo script not started, restarting it:")
        logging.info("Fifo script not started, restarting it")
        ret = os.system("/home/fap/fifo.sh &")
        logging.info(f"fifo.sh started, return code: {ret}")
        time.sleep(1)
    else:
        print("Fifo script id is: ", fifo_id)
        logging.info(f"Fifo script id is: {fifo_id}")
    ret = os.system("/home/fap/tshark.sh &")
    logging.info(f"tshark.sh started, return code: {ret}")
    time.sleep(2)


# Manage input of --multiple
# Extract ips and fqdn
# Each IP is submitted to the ipset WL, every other entry is handled as a fqdn
# and inserted into the unbound WL, it just does not care about any values ... (be careful)
def manageListOfEntries(loe):
    logging.info(loe)
    result = loe.split(",")
    ip_list = []
    fqdn_list = []
    for r in result:
        # Check IP
        if checkIP(r):
            logging.info(r + " is a valid IP-address")
            ip_list.append(r)
        else:
            fqdn_list.append(r)
    for ip in ip_list:
        addIPtoFirewall(ip)
    return fqdn_list


# Check, if the given parameter is a valid ip-address

def checkIP(ip):
    logging.info(f"checkIP called with: {ip}")
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False

# All necessary steps to create a secure environment based on unbound
def unbound_mgmt(target_list):
    logging.info(target_list)
    target = target_list[0]
    type_of_target = target_list[1]  # 1 = template, 2= unqiue, 3 = list
    print_delimiter()
    print("Creating unbound setup to whitelist for", target)

    if os.path.exists(UNBOUND_CONF):  # check, if file is existing, otherwise FAP was disabled
        logging.info("Unbound whitelist file exists")
        copyfile(UNBOUND_CONF, "unbound_orig")  # backup
    else:
        copyfile("/etc/unbound/restricted", UNBOUND_CONF)

    if type_of_target == 1:
        dir = TEMPLATEDIR + "/" + target
        if os.path.exists(dir):
            logging.info("template file chosen")
            insert_template_file(target)
        else:
            print("Added invalid template file, please check '-i'")
            print(colored("Stopped because of an error", "red"))
            exit()
    elif type_of_target == 2:
        logging.info("Unique service")
        insert_single_line(target)
    else:
        logging.info("list of entries as targets")
        fqdn = manageListOfEntries(args.multiple)
        for name in fqdn:
            insert_single_line(name)

    os.system("systemctl restart unbound")


# Add a new line for the unique service
def insert_single_line(t):
    logging.info(f"insert_single_line called with: {t}")
    file = open(UNBOUND_CONF, "a")
    insert_line = "local-zone: \"" + t + "\" transparent\n"
    logging.info("%s", insert_line)
    file.write(insert_line)
    file.close()


# Add the content of a template file to unbound
def insert_template_file(t):
    print("Use template file ", t)
    file = open(UNBOUND_CONF, "a")
    t_file = TEMPLATEDIR + "/" + t
    template = open(t_file, "r")
    for line in template:
        if line[0] == ">":  # this is the name of the service of this templatefile
            logging.info(line[2:])
            print(f"Service {line[2:-1]} choosen")
        elif line[0] == "+":  # this is an ip-address and no fqdn, just add it to ipset WL
            logging.info(line[:])
            addIPtoFirewall(line[1:])
        else:
            insert_line = "local-zone: " + line.rstrip() + " transparent\n"
            print("Adding ", insert_line, end='')
            file.write(insert_line)
    file.close()
    template.close()


# finally, let's start fapping
def fap_start(acl, target_list):
    logging.info(f"fap_start called with acl={acl}, target_list={target_list}")
    if acl == "WL":
        unbound_mgmt(target_list)
    #   else:
    #      novelty_detection()
    print_delimiter()
    print(">> Enabling ip_forwarding:")
    os.system("sysctl -w net.ipv4.ip_forward=1")
    start_tshark()
    # Finally, happy fapping
    start = timeit.default_timer()
    print_delimiter()
    print("Started fapping at " + getTime() + " ;-)")
    print("Here are some information:")
    print("----------------------------")
    print("PID of running tshark-process " + colored(str(get_pid("tshark")), "yellow"))
    #print("Press 'x' to stop the process")
    print("Press any other key for status information")
    stop = ""
    while True:
        stop = input("Please press a key to display status, 'x' to stop\n")
        if (stop.lower() == "x"):
            t = getTime()
            reset_ALL(t)
            ende = timeit.default_timer()
            print("Finished fapping at", t)
            createStats(start, ende)
            exit()
        else:
            print(colored("Display status:", "green"))
            jetzt = timeit.default_timer()
            print("Duration of current process: ", jetzt - start)
            getStatus()


# Reset all values and the environemnt
def reset_ALL(t):
    logging.info(f"reset_ALL called at {t}")
    # Reset unbound
    print("Restore unbound")
    copyfile("unbound_orig", UNBOUND_CONF)  # backup
    # Store ipset output in textfile
    uhr = formatTime(getTime())
    filename = "iplist_" + uhr + ".txt"
    export = "ipset list WL >>" + filename
    print("Preserve iplist entries in " + filename)
    os.system(export)
    # Flush ipset
    os.system("ipset flush WL")
    print("Stopping capture process")
    id = get_pid("tshark")
    id = id.decode("utf-8")
    array = id.split("\n")
    if (len(array) > 2):
        for elem in array:
            if len(elem) > 0:
                print("Killing process " + elem)
                string = "kill " + elem
                os.system(string)
    else:
        print("Get relevant id of process: ", id.rstrip())
        print("Killing process id ", id.rstrip())
        string = "kill " + id
        os.system(string)
    print("Finished process")
    print("Capture file with dns request is stored at '/home/fap/pcap/capture_" + formatTime(t) + ".pcap'")
    os.system("sudo mv /home/fap/pcap/test.pcap /home/fap/pcap/capture_" + formatTime(t) + ".pcap")
    os.system("sudo chown fap:fap /home/fap/pcap/capture_" + formatTime(t) + ".pcap")
    print("Restart lighttpd web interface")
    os.system("systemctl start lighttpd")


# Create the correct environment based on the choosen parameters
# return true, if real investigation is requested; all other params request info or status
def createEnv():
    logging.info("createEnv called")
    logging.info("Arguments: %s", args)
    # Which access control is choosen?
    if args.status:
        getStatus()
        return False
    elif args.info:
        listServices()
        return False
    else:
        getControl()
        return True


# Get the application, which should be permitted
def getApp():
    logging.info("getApp called")
    if (args.target == None) and (args.unique == None) and (args.multiple == None):
        print("Please choose an application by the '-t' parameter or a unique target by '-u' or a list by '--multiple'")
        return False
    else:
        if(args.target is not None):
            print("Choosen template file is: %s" % args.target)
        elif (args.unique is not None):
            print("Choosen unique target is " + colored(args.unique, "yellow"))
        else:
            print("Choosen list of targets is " + colored(args.multiple, "yellow"))
        return True


# Return the choosen single website
def getUniqueApp():
    logging.info("getUniqueApp called")
    print(args.unique)


# Returns a list of target and boolean value of uniqueness
# if template, return of is args.target and 1
# otherwise it is unique and 2 or list and 3
# To be honest, this seems to be not very useful
def getTarget():
    logging.info("getTarget called")
    if(args.target is not None):
        return (args.target, 1)
    if (args.unique is not None):
        return (args.unique, 2)
    if (args.multiple is not None):
        return (args.multiple, 3)

# List all available services (new)
def listServices():
    logging.info("listServices called")
    print("Available templates for filtering in the new version")
    if not args.debug:
        print(colored("Choose debug mode (-d) for a lists of entries", "blue"))
    files = glob.glob(TEMPLATEDIR+"/*.txt") # structure is ['/home/fap/template/dummy.txt']
    for file in files:
        filename = file.split("/")[4]
        with open(file) as f:
            print(colored(f.readline()[1:].lstrip()[:-1] + " - " + filename, "cyan"))
            if args.debug:
                print(colored(f.read(),"magenta"))
    

# List all available services
# def listServices_old():
#     # get data
#     if args.debug:
#         createServiceList(DATADIR)
#     else:
#         print("Available templates for filtering")
#         print(colored("Choose debug mode (-d) for a lists of fqdn", "blue"))
#         sm = serviceMapping()
#         print("Service \t Filename")
#         print("--------\t ---------")
#         for k in sm.keys():
#             # Formatting foo
#             tab = "\t"
#             if len(k) < 7:
#                 tab = "\t\t"
#             print(k, tab, sm[k], end="")


# Stop FAP and finish limitation in network name translation
def stopFAP():
    logging.info("stopFAP called")
    print("Stopping FAP and returning to unsecure environment")
    # Unbound reset
    os.system("mv /etc/unbound/unbound.conf.d/whitelist.conf /etc/unbound/restricted")
    os.system("/etc/init.d/unbound restart")


# Create a new WLAN environment
def restartWLAN():
    logging.info("restartWLAN called")
    print("WLAN settings will be erased...")
    os.system("/home/fap/src/hostapd_start.sh")
    os.system("sudo hostapd -B /etc/hostapd.conf")
    print("New WLAN Settings enabled")
    getWlanStatus()
    exit()

# Create a new WLAN environment
# Not the best solution, because we use a specific delimiter (:) which might appear in a SSID or PSK
# I should improve it with subprocess....
def defineWLAN(values):
    logging.info(f"defineWLAN called with values: {values}")
    print("WLAN settings will be set to given values...", values)
    ssid: str = values.split(":")[0]
    key: str = values[len(ssid)+1:]
    cmd = "/home/fap/src/hostapd_defined_start.sh " + ssid + " "  + key
    os.system(cmd)
    os.system("sudo hostapd -B /etc/hostapd.conf")
    print("New WLAN Settings enabled")
    getWlanStatus()
    exit()

# Repair corrupted dns-settings
def resetUnbound():
    logging.info("resetUnbound called")
    os.system("cp src/unbound_start /etc/unbound/restricted")
    copyfile("/etc/unbound/restricted", UNBOUND_CONF)
    os.system("/etc/init.d/unbound restart")

# Ausgabeverzeichnis setzen
def getOutputDirectory():
    logging.info("getOutputDirectory called")
    ts = formatTime(getTime())
    if args.output:
        o = args.output
        # Check if output dir exists, and ends with "/"
        if os.path.isdir(o):
            if o[-1] != "/":
                o = o + "/"
            # create filename
            pcapfile = o + "non_expert_" + ts + ".pcap"
            print(colored("Output directory set to " + o, "green"))
            print(">> Will copy all network packets to file: " + pcapfile)
            print(colored("Enable write permission of " + o + " for user root", "yellow"))
            os.system("chmod o+w " + o)
            os.system("sudo tshark -Q -i wlan0 -w " + pcapfile + "&")
        else:
            print(colored("Wrong output directory for pcap export. Please check parameter -o ", "red"))
            exit()

    else:
        # Check for installation type and second nic
        if not check_2nd_nic():
            print(colored("No output directory given, FAP will not capture any data", "red"))
            #pcapfile = "/var/www/html/non_expert_" + ts + ".pcap"
            #os.system("sudo tshark -Q -i wlan0 -w " + pcapfile + "&")


# Determine the correct initalisation of the OVS-mirror
def check_2nd_nic():
    if "dummy0" in os.listdir('/sys/class/net/'):
        return False
    else:
        return True


# Add the IP address to the ipset WL, useful for hardcoded IP addresses without any assigned DNS-request
def addIPtoFirewall(ip):
    string = "ipset add WL " + ip
    # print the full IP (don't strip characters)
    print(colored("Added IP address " + ip + " to iptables whitelist", "green"))
    os.system(string)


# Start
if __name__ == '__main__':
    if len(sys.argv) == 1:
        print(colored("Invalid Choice, please tell me what to do", "red"))  # Error at parameter list
    else:
        if args.version:
            print("Version: " + VERSION)
            print("Release: " + DATUM)
            getWlanStatus()
            exit()
        if args.wlan:
            print("Reset WLAN settings")
            restartWLAN()
        if args.ipv6:
            print("Checking IPv6")
            testIPv6()
            exit()
        if args.nameservice:
            print(colored("Resetting Unbound Nameservice configuration for whitelisting","magenta"))
            resetUnbound()
            exit()
        if args.set:
            defineWLAN(args.set)
            exit()

        


        if args.finish:  # reset FAP
            stopFAP()
            print(colored("FAP stopped, unsecure environment active", "red"))
            print("To reduce risk of misconfiguration, ip_forwarding -> disabled")
            os.system("sysctl -w net.ipv4.ip_forward=0")
        else:                  # Start FAP process with some initial checks
            is_env_ready = createEnv()
            if is_env_ready:
                appstart = getApp()
                if appstart:
                    print(colored("Environment ok, lets start", "green"))
                    # Stop webinterface to eradicate conflicts
                    print("Stopping webinterface")
                    os.system("systemctl stop lighttpd")
                    # Define output
                    output = getOutputDirectory()
                    if output is None:
                        output = "/var/www/html/"
                    fap_start(getControl(), getTarget())
                else:
                    print(colored("Error. Please correct misconfiguration and start again", "red"))
