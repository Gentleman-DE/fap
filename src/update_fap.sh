#!/bin/bash
set -euo pipefail

REPO_URL="https://github.com/Gentleman-DE/fap.git"
CLONE_DIR="/tmp/fap_update_$$"
BRANCH=""
EXPERT=0
COPY_TEMPLATES=0

usage() {
    echo "Usage: $0 [-b branch/tag] [-e] [-t]"
    echo ""
    echo "Options:"
    echo "  -b <branch|tag>   Checkout a specific branch or tag (default: repo default branch)"
    echo "  -e                Expert mode: use ovs.sh instead of ovs_dummy.sh"
    echo "  -t                Overwrite templates (skipped by default to preserve local edits)"
    echo "  -h                Show this help"
    exit 1
}

while getopts "b:eth" opt; do
    case $opt in
        b) BRANCH="$OPTARG" ;;
        e) EXPERT=1 ;;
        t) COPY_TEMPLATES=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root."
    exit 1
fi

echo "============================================="
echo " FAP Update Script"
echo "============================================="
echo " Repo:      $REPO_URL"
echo " Branch:    ${BRANCH:-default}"
echo " Expert:    $EXPERT"
echo " Templates: $( [ "$COPY_TEMPLATES" -eq 1 ] && echo 'overwrite' || echo 'keep local' )"
echo "============================================="
echo ""

cleanup() {
    echo "Cleaning up temp directory..."
    rm -rf "$CLONE_DIR"
}
trap cleanup EXIT

echo ">>> Cloning repository..."
git clone --depth 1 ${BRANCH:+--branch "$BRANCH"} "$REPO_URL" "$CLONE_DIR"

cd "$CLONE_DIR"
echo ">>> Checked out: $(git log --oneline -1)"
echo ""

echo ">>> Stopping services before update..."
systemctl stop hostapd 2>/dev/null || true
systemctl stop lighttpd 2>/dev/null || true

echo ">>> Copying src/ files..."
cp -v ./src/hostapd* /home/fap/src/
cp -v ./src/wlan0 /etc/network/interfaces.d/
cp -v ./src/unbound* /home/fap/src/
cp -v ./src/rc.local /etc/
cp -v ./src/index.html /var/www/html/
cp -v ./src/dnsmasq.conf /etc/
cp -v ./src/dhcpv6.conf /etc/dnsmasq.d/dhcpv6.conf
cp -v ./src/forward.txt /home/fap/src/forward.txt
cp -v ./src/forward6.txt /home/fap/src/forward6.txt

if [ "$EXPERT" -eq 1 ]; then
    cp -v ./src/ovs.sh /home/fap/src/ovs.sh
else
    cp -v ./src/ovs_dummy.sh /home/fap/src/ovs.sh
fi
chmod a+x /home/fap/src/ovs.sh

echo ">>> Copying main application..."
cp -v ./fap.py /home/fap/

echo ">>> Copying lib/..."
mkdir -p /home/fap/lib
cp -Rv ./lib/* /home/fap/lib/

echo ">>> Copying clean/..."
cp -Rv ./clean /home/fap/

if [ "$COPY_TEMPLATES" -eq 1 ]; then
    echo ">>> Copying templates (overwriting local)..."
    mkdir -p /home/fap/template
    cp -v ./template/* /home/fap/template/
else
    echo ">>> Skipping templates (use -t to overwrite)"
fi

echo ">>> Creating directories..."
mkdir -p /home/fap/logs
mkdir -p /home/fap/pcap

echo ">>> Setting permissions..."
chmod a+x /home/fap/*.py 2>/dev/null || true
chmod a+x /home/fap/src/*.sh
chmod a+x /etc/rc.local
chown -R fap:fap /home/fap/*

echo ">>> Loading firewall rules..."
iptables-restore < /home/fap/src/forward.txt
ip6tables-restore < /home/fap/src/forward6.txt

echo ">>> Restarting services..."
systemctl restart unbound 2>/dev/null || true
systemctl restart dnsmasq 2>/dev/null || true
systemctl start lighttpd 2>/dev/null || true

echo ""
echo "============================================="
echo " Update complete!"
echo "============================================="
iptables -L FORWARD -v -n --line-numbers
echo ""
ip6tables -L FORWARD -v -n --line-numbers
echo "============================================="