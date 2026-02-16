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
import subprocess
import threading

VERSION = "0.9.0"
DATUM = "16.02.2026"
DATADIR = "/var/www/html/fap/messenger"
TEMPLATEDIR = "/home/fap/template"
HOMEDIR = "/home/fap/src/"
UNBOUND_CONF = "/etc/unbound/unbound.conf.d/whitelist.conf"
LOOPBACK_IPS = {"127.0.0.1", "0.0.0.0", "::1", "::"}

session = None


class SessionLogger:
    def __init__(self):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.session_dir = f'/home/fap/logs/{timestamp}'
        os.makedirs(self.session_dir, exist_ok=True)

        self.logger = logging.getLogger('fap')
        self.logger.setLevel(logging.DEBUG)
        self.logger.handlers.clear()

        fh = logging.FileHandler(f'{self.session_dir}/full.log')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        self.logger.addHandler(ch)

        self.allowed_file = open(f'{self.session_dir}/allowed_domains.log', 'a')
        self.allowed_file.write("# Allowed domains - resolved to real IPs\n")
        self.allowed_file.write(f"# Session started: {timestamp}\n")
        self.allowed_file.write(f"# {'Timestamp':<26} {'Domain':<50} {'IP'}\n")
        self.allowed_file.write(f"# {'-'*26} {'-'*50} {'-'*40}\n")
        self.allowed_file.flush()

        self.blocked_file = open(f'{self.session_dir}/blocked_domains.log', 'a')
        self.blocked_file.write("# Blocked domains - redirected to loopback\n")
        self.blocked_file.write(f"# Session started: {timestamp}\n")
        self.blocked_file.write(f"# {'Timestamp':<26} {'Domain':<50} {'Loopback IP'}\n")
        self.blocked_file.write(f"# {'-'*26} {'-'*50} {'-'*40}\n")
        self.blocked_file.flush()

        self._seen_allowed = set()
        self._seen_blocked = set()
        self._lock = threading.Lock()

        self.logger.info(f"Session directory created: {self.session_dir}")

    def info(self, msg):
        self.logger.info(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def error(self, msg):
        self.logger.error(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def log_allowed(self, domain, ip):
        with self._lock:
            key = (domain, ip)
            if key in self._seen_allowed:
                return
            self._seen_allowed.add(key)
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            line = f"{ts}  {domain:<50} {ip}\n"
            self.allowed_file.write(line)
            self.allowed_file.flush()
            self.logger.debug(f"ALLOWED: {domain} -> {ip}")

    def log_blocked(self, domain, loopback_ip):
        with self._lock:
            key = (domain, loopback_ip)
            if key in self._seen_blocked:
                return
            self._seen_blocked.add(key)
            ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            line = f"{ts}  {domain:<50} {loopback_ip}\n"
            self.blocked_file.write(line)
            self.blocked_file.flush()
            self.logger.debug(f"BLOCKED: {domain} -> {loopback_ip}")

    def get_pcap_path(self):
        return f'{self.session_dir}/capture.pcap'

    def get_session_dir(self):
        return self.session_dir

    def write_summary(self, start_time, end_time):
        summary_path = f'{self.session_dir}/summary.txt'
        duration = end_time - start_time
        with open(summary_path, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write("FAP Session Summary\n")
            f.write("=" * 60 + "\n")
            f.write(f"Duration:         {duration:.2f} seconds\n")
            f.write(f"Allowed domains:  {len(self._seen_allowed)}\n")
            f.write(f"Blocked domains:  {len(self._seen_blocked)}\n")
            f.write(f"Session dir:      {self.session_dir}\n")
            f.write("=" * 60 + "\n")
            f.write("\nFiles in this session:\n")
            f.write(f"  full.log              - Complete debug log\n")
            f.write(f"  allowed_domains.log   - Whitelisted domains with resolved IPs\n")
            f.write(f"  blocked_domains.log   - Blocked domains redirected to loopback\n")
            f.write(f"  capture.pcap          - Full packet capture\n")
        self.logger.info(f"Summary written to {summary_path}")

    def close(self):
        self.logger.info("Session ended, closing log files")
        self.allowed_file.close()
        self.blocked_file.close()
        for handler in self.logger.handlers[:]:
            handler.close()
            self.logger.removeHandler(handler)


def init_session():
    global session
    session = SessionLogger()
    return session


parser = argparse.ArgumentParser(
    description="FAP CLI", prog='fap.py', usage='%(prog)s [options]'
)
parser.add_argument("-m", "--multiple", help="list multiple targets, IP as well as FQDN")
parser.add_argument("-t", "--target", help="Target service, Use -i for a list")
parser.add_argument("-u", "--unique", help="Limit traffic to ONE unique system or FQDN")
parser.add_argument("-o", "--output", help="Create pcap-file in given directory")
parser.add_argument("-d", "--debug", help="Print debug information", action="store_true")
parser.add_argument("-v", "--version", help="Print information of FAP", action="store_true")
group = parser.add_mutually_exclusive_group()
group.add_argument("-i", "--info", help="List available apps", action="store_true")
group.add_argument("-s", "--status", help="Display current status", action="store_true")
group.add_argument("-w", "--wlan", help="Restart WLAN-Session", action="store_true")
group.add_argument("-n", "--nameservice", help="Clear misconfigured Unbound-Nameservice", action="store_true")
group.add_argument("-x", "--finish", help="Create an unsecure environment for updating FAP", action="store_true")
group.add_argument("-6", "--ipv6", help="Check IPv6 configuration", action="store_true")
group.add_argument("--set", help="Define the SSID and Key for a known wifi-env")
args = parser.parse_args()


def is_ipv6(ip_str):
    try:
        ipaddress.IPv6Address(ip_str)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_loopback(ip_str):
    ip_str = ip_str.strip()
    if ip_str in LOOPBACK_IPS:
        return True
    try:
        return ipaddress.ip_address(ip_str).is_loopback
    except ValueError:
        return False


def add_ip_to_ipset(ip: str):
    ip = ip.strip()
    if not ip:
        return

    try:
        if is_ipv6(ip):
            ipset_name = "WL6"
        else:
            ipset_name = "WL"

        subprocess.run(
            ["sudo", "ipset", "add", ipset_name, ip],
            check=False,
            capture_output=True
        )
        if session:
            session.info(f"ip added {ip} to {ipset_name}")
    except Exception as e:
        if session:
            session.error(f"Failed to add IP {ip}: {e}")


def process_line(line: str):
    line = line.strip()
    if not line:
        return

    parts = line.split("\t")

    domain = parts[0].strip() if len(parts) > 0 else ""
    ipv4 = parts[1].strip() if len(parts) > 1 else ""
    ipv6 = parts[2].strip() if len(parts) > 2 else ""

    resolved_ips = []
    if ipv4:
        resolved_ips.extend(ipv4.split(","))
    if ipv6:
        resolved_ips.extend(ipv6.split(","))

    for ip in resolved_ips:
        ip = ip.strip()
        if not ip:
            continue

        if is_loopback(ip):
            if session and domain:
                session.log_blocked(domain, ip)
        else:
            if session and domain:
                session.log_allowed(domain, ip)
            add_ip_to_ipset(ip)


def start_tshark():
    print_delimiter()
    print(">> Starting tshark")
    if session:
        session.info("Starting tshark")

    tshark_cmd = [
        "tshark",
        "-i", "wlan0",
        "-f", "src port 53",
        "-l",
        "-w", "/tmp/test.pcap",
        "-T", "fields",
        "-e", "dns.qry.name",
        "-e", "dns.a",
        "-e", "dns.aaaa",
        "-E", "occurrence=f"
    ]

    try:
        process = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        if session:
            session.info(f"tshark started with PID: {process.pid}")
        print(f"tshark started with PID: {process.pid}")

        def read_output():
            for line in process.stdout:
                if session:
                    session.debug(f"tshark output: {line.strip()}")
                process_line(line)

        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()

        return process

    except Exception as e:
        if session:
            session.error(f"Failed to start tshark: {e}")
        print(f"Failed to start tshark: {e}")
        return None


def manageListOfEntries(loe):
    if session:
        session.info(loe)
    result = loe.split(",")
    ip_list = []
    ipv6_list = []
    fqdn_list = []
    for r in result:
        if checkIP(r):
            if is_ipv6(r):
                if session:
                    session.info(r + " is a valid IPv6 address")
                ipv6_list.append(r)
            else:
                if session:
                    session.info(r + " is a valid IPv4 address")
                ip_list.append(r)
        else:
            fqdn_list.append(r)
    for ip in ip_list:
        addIPtoFirewall(ip)
    for ipv6 in ipv6_list:
        addIPv6toFirewall(ipv6)
    return fqdn_list


def checkIP(ip):
    if session:
        session.info(f"checkIP called with: {ip}")
    try:
        ipaddress.ip_address(ip)
        return True
    except:
        return False


def unbound_mgmt(target_list):
    if session:
        session.info(target_list)
    target = target_list[0]
    type_of_target = target_list[1]
    print_delimiter()
    print("Creating unbound setup to whitelist for", target)

    if os.path.exists(UNBOUND_CONF):
        if session:
            session.info("Unbound whitelist file exists")
        copyfile(UNBOUND_CONF, "unbound_orig")
    else:
        copyfile("/home/fap/src/unbound_start", UNBOUND_CONF)

    if type_of_target == 1:
        dir = TEMPLATEDIR + "/" + target
        if os.path.exists(dir):
            if session:
                session.info("template file chosen")
            insert_template_file(target)
        else:
            print("Added invalid template file, please check '-i'")
            print(colored("Stopped because of an error", "red"))
            exit()
    elif type_of_target == 2:
        if session:
            session.info("Unique service")
        insert_single_line(target)
    else:
        if session:
            session.info("list of entries as targets")
        fqdn = manageListOfEntries(args.multiple)
        for name in fqdn:
            insert_single_line(name)

    os.system("systemctl restart unbound")


def insert_single_line(t):
    if session:
        session.info(f"insert_single_line called with: {t}")
    file = open(UNBOUND_CONF, "a")
    insert_line = "    local-zone: \"" + t + "\" transparent\n"
    if session:
        session.info("%s" % insert_line)
    file.write(insert_line)
    file.close()


def insert_template_file(t):
    print("Use template file ", t)
    file = open(UNBOUND_CONF, "a")
    t_file = TEMPLATEDIR + "/" + t
    template = open(t_file, "r")
    for line in template:
        if line[0] == ">":
            if session:
                session.info(line[2:])
            print(f"Service {line[2:-1]} choosen")
        elif line[0] == "+":
            if session:
                session.info(line[:])
            ip_entry = line[1:].strip()
            if is_ipv6(ip_entry):
                addIPv6toFirewall(ip_entry)
            else:
                addIPtoFirewall(ip_entry)
        else:
            insert_line = "    local-zone: " + line.rstrip() + " transparent\n"
            print("Adding ", insert_line, end='')
            file.write(insert_line)
    file.close()
    template.close()


def fap_start(acl, target_list):
    if session:
        session.info(f"fap_start called with acl={acl}, target_list={target_list}")
    if acl == "WL":
        unbound_mgmt(target_list)
    print_delimiter()
    print(">> Enabling ip_forwarding:")
    os.system("sysctl -w net.ipv4.ip_forward=1")
    os.system("sysctl -w net.ipv6.conf.all.forwarding=1")
    os.system("systemctl restart dnsmasq")
    start_tshark()
    start = timeit.default_timer()
    print_delimiter()
    print("Started fapping at " + getTime() + " ;-)")
    print("Here are some information:")
    print("----------------------------")
    print("PID of running tshark-process " + colored(str(get_pid("tshark")), "yellow"))
    if session:
        print("Session logs: " + colored(session.get_session_dir(), "cyan"))
    print("Press any other key for status information")
    stop = ""
    while True:
        stop = input("Please press a key to display status, 'x' to stop\n")
        if (stop.lower() == "x"):
            t = getTime()
            ende = timeit.default_timer()
            if session:
                session.write_summary(start, ende)
            reset_ALL(t)
            print("Finished fapping at", t)
            createStats(start, ende)
            if session:
                session.close()
            exit()
        else:
            print(colored("Display status:", "green"))
            jetzt = timeit.default_timer()
            print("Duration of current process: ", jetzt - start)
            if session:
                print(f"Allowed domains so far: {len(session._seen_allowed)}")
                print(f"Blocked domains so far: {len(session._seen_blocked)}")
            getStatus()


def reset_ALL(t):
    if session:
        session.info(f"reset_ALL called at {t}")
    print("Restore unbound")
    copyfile("unbound_orig", UNBOUND_CONF)

    uhr = formatTime(getTime())

    if session:
        filename = f"{session.get_session_dir()}/iplist.txt"
    else:
        filename = "iplist_" + uhr + ".txt"

    print("Preserve iplist entries in " + filename)
    os.system("ipset list WL >> " + filename)
    os.system("ipset list WL6 >> " + filename)

    os.system("ipset flush WL")
    os.system("ipset flush WL6")

    print("Stopping capture process")
    try:
        id = get_pid("tshark")
        id = id.decode("utf-8").strip()
        array = id.split("\n")
        if len(array) > 1:
            for elem in array:
                if len(elem) > 0:
                    print("Killing process " + elem)
                    os.system("kill " + elem)
        else:
            if id:
                print("Killing process id ", id)
                os.system("kill " + id)
    except subprocess.CalledProcessError:
        if session:
            session.warning("No tshark process found to kill (already exited)")
        print(colored("No tshark process found (already stopped)", "yellow"))
    except Exception as e:
        if session:
            session.error(f"Error stopping tshark: {e}")
        print(colored(f"Error stopping tshark: {e}", "red"))

    print("Finished process")

    if session:
        pcap_dest = session.get_pcap_path()
        copyfile("/tmp/test.pcap", pcap_dest)
        os.remove("/tmp/test.pcap")
        print(f"Capture file stored at '{pcap_dest}'")
    else:
        pcap_dest = "/home/fap/pcap/capture_" + formatTime(t) + ".pcap"
        copyfile("/tmp/test.pcap", pcap_dest)
        os.remove("/tmp/test.pcap")
        print("Capture file with dns request is stored at '" + pcap_dest + "'")

    print("Restart lighttpd web interface")
    os.system("systemctl start lighttpd")


def createEnv():
    if session:
        session.info("createEnv called")
        session.info("Arguments: %s" % args)
    if args.status:
        getStatus()
        return False
    elif args.info:
        listServices()
        return False
    else:
        getControl()
        return True


def getApp():
    if session:
        session.info("getApp called")
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


def getUniqueApp():
    if session:
        session.info("getUniqueApp called")
    print(args.unique)


def getTarget():
    if session:
        session.info("getTarget called")
    if(args.target is not None):
        return (args.target, 1)
    if (args.unique is not None):
        return (args.unique, 2)
    if (args.multiple is not None):
        return (args.multiple, 3)


def listServices():
    if session:
        session.info("listServices called")
    print("Available templates for filtering in the new version")
    if not args.debug:
        print(colored("Choose debug mode (-d) for a lists of entries", "blue"))
    files = glob.glob(TEMPLATEDIR + "/*.txt")
    for file in files:
        filename = file.split("/")[4]
        with open(file) as f:
            print(colored(f.readline()[1:].lstrip()[:-1] + " - " + filename, "cyan"))
            if args.debug:
                print(colored(f.read(), "magenta"))


def stopFAP():
    if session:
        session.info("stopFAP called")
    print("Stopping FAP and returning to unsecure environment")
    os.system("mv /etc/unbound/unbound.conf.d/whitelist.conf /etc/unbound/restricted")
    os.system("/etc/init.d/unbound restart")


def restartWLAN():
    if session:
        session.info("restartWLAN called")
    print("WLAN settings will be erased...")
    os.system("/home/fap/src/hostapd_start.sh")
    os.system("sudo hostapd -B /etc/hostapd.conf")
    print("New WLAN Settings enabled")
    getWlanStatus()
    exit()


def defineWLAN(values: str):
    if session:
        session.info(f"defineWLAN called with values: {values}")
    print("WLAN settings will be set to given values...", values)

    if ":" not in values:
        if session:
            session.error("Invalid WLAN values. Expected format 'SSID:KEY'")
        print("Invalid WLAN values. Expected format 'SSID:KEY'")
        exit(1)
    ssid, key = values.split(":", 1)
    ssid = ssid.strip()
    key = key.strip()
    if not ssid or not key:
        if session:
            session.error("SSID or KEY empty after parsing")
        print("SSID or KEY cannot be empty")
        exit(1)

    hostapd_conf_src = "/home/fap/src/hostapd.conf"
    hostapd_conf_dst = "/etc/hostapd.conf"

    def run(cmd, check=True, log_stdout=True, log_stderr=True):
        try:
            if session:
                session.debug(f"run: {' '.join(cmd)}")
            res = subprocess.run(
                cmd, check=check, capture_output=True, text=True
            )
            if log_stdout and res.stdout and session:
                session.debug(res.stdout.strip())
            if log_stderr and res.stderr and session:
                session.debug(res.stderr.strip())
            return res
        except subprocess.CalledProcessError as e:
            if session:
                session.error(
                    f"Command failed: {' '.join(cmd)}; "
                    f"rc={e.returncode}; stdout={e.stdout}; stderr={e.stderr}"
                )
            if check:
                print(f"Command failed: {' '.join(cmd)}")
                exit(1)
            return e

    def ensure_masquerade_rule():
        cmd_check = [
            "sudo", "iptables", "-t", "nat", "-C",
            "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE",
        ]
        cmd_add = [
            "sudo", "iptables", "-t", "nat", "-A",
            "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE",
        ]
        cmd_check_ipv6 = [
            "sudo", "ip6tables", "-t", "nat", "-C",
            "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE",
        ]
        cmd_add_ipv6 = [
            "sudo", "ip6tables", "-t", "nat", "-A",
            "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE",
        ]

        res = subprocess.run(cmd_check, capture_output=True, text=True)
        if res.returncode == 0:
            if session:
                session.debug("IPv4 MASQUERADE rule already present")
        else:
            if session:
                session.debug("IPv4 MASQUERADE rule missing; adding it")
            add = subprocess.run(cmd_add, capture_output=True, text=True)
            if add.returncode != 0 and session:
                session.error(f"Failed to add IPv4 MASQUERADE rule: {add.stderr.strip()}")

        res_ipv6 = subprocess.run(cmd_check_ipv6, capture_output=True, text=True)
        if res_ipv6.returncode == 0:
            if session:
                session.debug("IPv6 MASQUERADE rule already present")
        else:
            if session:
                session.debug("IPv6 MASQUERADE rule missing; adding it")
            add_ipv6 = subprocess.run(cmd_add_ipv6, capture_output=True, text=True)
            if add_ipv6.returncode != 0 and session:
                session.error(f"Failed to add IPv6 MASQUERADE rule: {add_ipv6.stderr.strip()}")

    run(["sudo", "systemctl", "stop", "hostapd"], check=False)
    run(["sudo", "killall", "hostapd"], check=False)
    run(["sudo", "rfkill", "unblock", "wlan"])
    run(["sudo", "ip", "link", "set", "wlan0", "down"])
    run(["sudo", "ip", "link", "set", "wlan0", "up"])
    ensure_masquerade_rule()
    run(["sudo", "ip", "addr", "flush", "dev", "wlan0"], check=False)
    run(["sudo", "ip", "addr", "add", "10.98.76.5/24", "dev", "wlan0"])
    run(["sudo", "ip", "addr", "add", "fd00::1/64", "dev", "wlan0"])
    run(["sudo", "ip", "-6", "addr", "add", "fe80::1/64", "dev", "wlan0", "scope", "link"])

    try:
        copyfile(hostapd_conf_src, hostapd_conf_dst)
        with open(hostapd_conf_dst, "a") as f:
            f.write(f"\nssid={ssid}\n")
            f.write(f"wpa_passphrase={key}\n")
        if session:
            session.info(f"hostapd.conf written to {hostapd_conf_dst} with ssid={ssid}")
    except Exception as e:
        if session:
            session.error(f"Failed to write hostapd.conf: {e}")
        print("Failed to configure hostapd")
        exit(1)

    run(["sudo", "hostapd", "-B", "/etc/hostapd.conf"])
    run(["sudo", "systemctl", "restart", "dnsmasq"])
    print("New WLAN Settings enabled")
    getWlanStatus()
    exit()


def resetUnbound():
    if session:
        session.info("resetUnbound called")
    copyfile("/home/fap/src/unbound_start", UNBOUND_CONF)
    os.system("systemctl restart unbound")


def getOutputDirectory():
    if session:
        session.info("getOutputDirectory called")
    ts = formatTime(getTime())
    if args.output:
        o = args.output
        if os.path.isdir(o):
            if o[-1] != "/":
                o = o + "/"
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
        if not check_2nd_nic():
            print(colored("No output directory given, FAP will not capture any data", "red"))


def check_2nd_nic():
    if "dummy0" in os.listdir('/sys/class/net/'):
        return False
    else:
        return True


def addIPtoFirewall(ip):
    ip = ip.strip()
    string = "ipset add WL " + ip
    print(colored("Added IP address " + ip + " to iptables whitelist", "green"))
    if session:
        session.info(f"Added IPv4 {ip} to firewall")
    os.system(string)


def addIPv6toFirewall(ip):
    ip = ip.strip()
    string = "ipset add WL6 " + ip
    print(colored("Added IPv6 address " + ip + " to iptables whitelist", "cyan"))
    if session:
        session.info(f"Added IPv6 {ip} to firewall")
    os.system(string)


if __name__ == '__main__':
    init_session()

    if len(sys.argv) == 1:
        print(colored("Invalid Choice, please tell me what to do", "red"))
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
            print(colored("Resetting Unbound Nameservice configuration for whitelisting", "magenta"))
            resetUnbound()
            exit()
        if args.set:
            defineWLAN(args.set)
            exit()

        if args.finish:
            stopFAP()
            print(colored("FAP stopped, unsecure environment active", "red"))
            print("To reduce risk of misconfiguration, ip_forwarding -> disabled")
            os.system("sysctl -w net.ipv4.ip_forward=0")
            os.system("sysctl -w net.ipv6.conf.all.forwarding=0")
        else:
            is_env_ready = createEnv()
            if is_env_ready:
                appstart = getApp()
                if appstart:
                    print(colored("Environment ok, lets start", "green"))
                    print("Stopping webinterface")
                    os.system("systemctl stop lighttpd")
                    output = getOutputDirectory()
                    if output is None:
                        output = "/var/www/html/"
                    fap_start(getControl(), getTarget())
                else:
                    print(colored("Error. Please correct misconfiguration and start again", "red"))