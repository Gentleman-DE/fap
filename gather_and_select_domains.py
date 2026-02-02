import curses
import os
import sys
import subprocess
import threading
import time
import shutil

TEMPLATE_DIR = '/home/fap/template'
IPTABLES_BACKUP = '/tmp/iptables_backup.rules'
IPSET_BACKUP = '/tmp/ipset_backup.dump'
UNBOUND_CONF = '/etc/unbound/unbound.conf.d/whitelist.conf'
UNBOUND_BACKUP = '/tmp/unbound_whitelist_backup.conf'

# Usage: python gather_and_select_domains.py [name]
# This script will capture DNS queries using tshark and let you select them interactively
# It will set permissive firewall rules and unbound config during gathering and restore them after selection

def backup_firewall():
    subprocess.call(['sudo', 'iptables-save', '-f', IPTABLES_BACKUP])
    subprocess.call(['sudo', 'ipset', 'save', '-f', IPSET_BACKUP])

def set_permissive_firewall():
    subprocess.call(['sudo', 'iptables', '-F'])
    subprocess.call(['sudo', 'iptables', '-P', 'INPUT', 'ACCEPT'])
    subprocess.call(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'])
    subprocess.call(['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'])
    subprocess.call(['sudo', 'ipset', 'flush'])
    subprocess.call(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])

def restore_firewall():
    if os.path.exists(IPTABLES_BACKUP):
        subprocess.call(['sudo', 'iptables-restore', IPTABLES_BACKUP])
        os.remove(IPTABLES_BACKUP)
    if os.path.exists(IPSET_BACKUP):
        subprocess.call(['sudo', 'ipset', 'restore', '-f', IPSET_BACKUP])
        os.remove(IPSET_BACKUP)

def backup_unbound():
    if os.path.exists(UNBOUND_CONF):
        shutil.copy(UNBOUND_CONF, UNBOUND_BACKUP)

def set_permissive_unbound():
    with open(UNBOUND_CONF, 'w') as f:
        f.write('server:\nlocal-zone: "." transparent\n')
    subprocess.call(['sudo', 'systemctl', 'restart', 'unbound'])

def restore_unbound():
    if os.path.exists(UNBOUND_BACKUP):
        shutil.copy(UNBOUND_BACKUP, UNBOUND_CONF)
        subprocess.call(['sudo', 'systemctl', 'restart', 'unbound'])
        os.remove(UNBOUND_BACKUP)

def run_tshark(name, stop_event):
    output_file = os.path.join(TEMPLATE_DIR, f'{name}_all.txt')
    if os.path.exists(output_file):
        os.remove(output_file)
    cmd = [
        'tshark', '-i', 'wlan0', '-Y', 'dns', '-T', 'fields', '-e', 'dns.qry.name'
    ]
    with open(output_file, 'w') as f:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.DEVNULL)
        while not stop_event.is_set():
            time.sleep(1)
        proc.terminate()
        proc.wait()

def main(stdscr, name):
    curses.curs_set(0)
    stdscr.clear()
    all_file = os.path.join(TEMPLATE_DIR, f'{name}_all.txt')
    select_file = os.path.join(TEMPLATE_DIR, f'{name}.txt')
    stop_event = threading.Event()
    # Backup and set permissive firewall and unbound
    backup_firewall()
    backup_unbound()
    set_permissive_firewall()
    set_permissive_unbound()
    # Start tshark in background
    tshark_thread = threading.Thread(target=run_tshark, args=(name, stop_event))
    tshark_thread.start()
    stdscr.addstr(0, 0, 'Gathering DNS queries... Press "s" to stop and select.')
    stdscr.refresh()
    # Wait for user to press 's' to stop gathering
    while True:
        key = stdscr.getch()
        if key == ord('s'):
            stop_event.set()
            tshark_thread.join()
            break
    # Restore firewall and unbound
    restore_firewall()
    restore_unbound()
    # Read all unique domains
    if not os.path.exists(all_file):
        stdscr.addstr(2, 0, f'No DNS queries captured.')
        stdscr.refresh()
        stdscr.getch()
        return
    with open(all_file, 'r') as f:
        domains = sorted(set(line.strip() for line in f if line.strip()))
    selected = set()
    idx = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, 'Arrow keys to move, "a" to toggle/add, "q" to quit')
        for i, domain in enumerate(domains):
            marker = '>' if i == idx else ' '
            sel = '[x]' if domain in selected else '[ ]'
            stdscr.addstr(i+2, 0, f'{marker} {sel} {domain}')
        key = stdscr.getch()
        if key == curses.KEY_UP:
            idx = max(0, idx-1)
        elif key == curses.KEY_DOWN:
            idx = min(len(domains)-1, idx+1)
        elif key == ord('a'):
            # Toggle selection
            if domains[idx] in selected:
                selected.remove(domains[idx])
            else:
                selected.add(domains[idx])
            # Move down one line after toggling
            if idx < len(domains)-1:
                idx += 1
        elif key == ord('q'):
            break
    # Write selected domains to select_file
    with open(select_file, 'w') as f:
        for domain in selected:
            f.write(domain + '\n')
    stdscr.clear()
    stdscr.addstr(0, 0, f'Selected domains saved to {select_file}')
    stdscr.refresh()
    stdscr.getch()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python gather_and_select_domains.py [name]')
        sys.exit(1)
    name = sys.argv[1]
    curses.wrapper(lambda stdscr: main(stdscr, name))
