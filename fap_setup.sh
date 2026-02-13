#!/bin/bash

# Dieses Skript macht aus einem Raspberry einen Forensischen Access Point
# Dafür werden verschiedene Programme installiert und konfiguriert




# Parameter für OVS
# Dieser Parameter regelt die Konfiguration des OVS-Mirror, der zur Laufzeit genutzt wird.
# In der Standardeinstellung leitet OVS alle Daten an die zweite NIC (eth1), in dem ein 
# Mirror zwischen eth0 und eth1 angelegt wird.
# Durch EXPERT=0 (oder was anderes als "1") wird ein virtuelles Dummyinterface angelegt, welches
# den Mirror von eth1 auf dummy0 umbiegt. Der Mirror existiert somit noch (sonst scheitern die Skripte später),
# spiegelt aber keine Daten mehr auf eth1 und benötigt eth1 somit nicht mehr
# EXPERT=1: OVS wird installiert und konfiguriert
# EXPERT=0: OVS wird installiert, aber nicht konfiguriert 
EXPERT=0


# Ab hier am besten nichts mehr ändern ;-)
VERSION="0.8.7"
DATE="2024-02-09"
INSTALLER="0.5"




echo "*************************************************"
echo "* Installiere FAP in der Version " $VERSION
echo "* Version des Installers: " $INSTALLER
echo "* Datum des Installers: " $DATE
echo "*************************************************"
echo "*"
echo "* Einstellungen der Netzwerkkarte: "
echo "* ---------------------------------"
echo "*"
if [[ "$EXPERT" -eq 1 ]]; 
then
echo "* >> Zweite Netzwerkkarte muss angeschlossen sein"
else
echo "* >> Zweite Netzwerkkarte darf fehlen"
fi
echo "*************************************************"
echo ""
echo "Bitte sicherstellen, dass die initiale Konfiguration mit"
echo "raspi-config erstellt wurde. Dies umfasst Lokalisation und WLAN."
echo "Bitte prüfen, ob die Einstellungen für die USB-NIC ok ist, "
echo "ansonsten bitte Abbrechen und korrigieren."
echo ""
echo ""
read -n1 -p "Alle Einstellungen richtig und fortfahren? [j,n]" doit
case $doit in
  j|J) echo "Ja" ;;
  n|N) echo "nein"; exit ;;
esac


# Initiale Installationen
apt-get update
apt-get upgrade -y
echo "*** Installiere git, vim und pwgen"
apt-get install -y vim git  pwgen ntpdate

# Initiale Deinstallationen
echo "*** Entferne avahi und dhcpcd5"
apt-get purge -y avahi-daemon dhcpcd5
apt-get -y autoremove
/etc/init.d/avahi-daemon stop

# Add fap-User
useradd -d /home/fap -G sudo -m -s /bin/bash fap 
echo "fap:1234" | chpasswd

# Verzeichnisse anlegen
mkdir /home/fap/src/
mkdir /home/fap/lib
mkdir /home/fap/pcap
mkdir /run/uuidd
chmod 777 /home/fap/pcap/


# Namen ändern
echo "fap" > /etc/hostname
sed -i s/raspberrypi/fap/g /etc/hosts
echo "Inhalt der /etc/hosts"
cat /etc/hosts
echo "Gesetzter Hostname"
cat /etc/hostname

# predictable interfaces names aktivieren
bash -c  'echo -n " net.ifnames=0 " >> /boot/cmdline.txt'
tr -d "\n" < /boot/cmdline.txt > /home/fap/cmdline
cp /home/fap/cmdline /boot/cmdline.txt
rm /home/fap/cmdline

# ipv6 deaktivieren
# ansonsten sind Seiteneffekte beim Auflösen der Namen möglich
#echo "*** Deaktiviere IPv6"
#rm /etc/modprobe.d/ipv6.conf
#bash -c 'echo -n "blacklist ipv6" >> /etc/modprobe.d/ipv6.conf' 

# Hostapd installieren und konfigurieren
echo "*** Installiere hostapd"
apt-get  -y install hostapd
cp ./src/hostapd* /home/fap/src/
cp ./src/wlan0 /etc/network/interfaces.d/
echo "interface wlan0" >> /etc/dhcpcd.conf
echo "static ip_address 10.98.76.5/24" >> /etc/dhcpcd.conf
echo "nohook wpa_supplicant" >> /etc/dhcpcd.conf
echo "DAEMON_CONF='/etc/hostapd.conf'" >> /etc/default/hostapd
ifconfig wlan0 up


# python fuer fap_cli
echo "*** Installiere Pythonmodule"
apt-get -y install python3-termcolor python3-netifaces

# DNS unbound
echo "*** Installiere Unbound"
apt-get -y install unbound
# cp ./src/local.conf /etc/unbound/unbound.conf.d/
# cp ./src/whitelist_user.conf /etc/unbound/unbound.conf.d/whitelist.conf

# Open vSwitch
echo "*** Installiere openvswitch" 
apt-get -y install openvswitch-common openvswitch-switch
export PATH=$PATH:/usr/local/share/openvswitch/scripts

if [[ "$EXPERT" -eq 1 ]]; 
then
  cp ./src/ovs.sh /home/fap/src/ovs.sh
else
  cp ./src/ovs_dummy.sh /home/fap/src/ovs.sh
fi

chmod a+x /home/fap/src/ovs.sh

# Lighttpd
echo "*** Installiere lighttpd"
apt-get -y install lighttpd 
apt-get -y install php8.2 php8.2-fpm php8.2-cgi
lighttpd-enable-mod fastcgi
lighttpd-enable-mod fastcgi-php
service lighttpd force-reload
/etc/init.d/lighttpd restart

# Munin für Statistiken
echo "*** Installiere munin"
apt-get -y install munin
ln -s /var/cache/munin/www /var/www/html/munin

# iptables und ipset
echo "*** Installiere ipset"
apt-get -y install ipset
cp ./src/forward.txt /home/fap/src/
cp ./src/forward6.txt /home/fap/src/
IP=`hostname -I | cut -d " " -f 1`
echo $IP

ipset add admin $IP 

# tshark
echo "*** Installiere tshark"
apt-get -y install debconf-utils
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
export DEBIAN_FRONTEND=noninteractive
apt-get -y install tshark
unset DEBIAN_FRONTEND

#dnsmasq
echo "*** Installiere dnsmasq"
apt-get -y install dnsmasq
cp ./src/dnsmasq.conf /etc/
cp ./src/dhcpv6.conf /etc/dnsmasq.d/dhcpv6.conf

# Fifo erstellen
echo "*** Erstelle fifo"
mkfifo /home/fap/ips
chown fap:fap /home/fap/ips

# Routing aktivieren
echo "*** Routing aktiveren"
sysctl -w net.ipv4.ip_forward=1
echo "1" > /proc/sys/net/ipv4/ip_forward

# Zeitzone korrigieren
echo "*** Korrigiere Zeitzone"
timedatectl set-timezone Europe/Berlin
ntpdate 1.de.pool.ntp.org

# Kopieren einiger Daten
echo "*** Kopiere Daten"
cp ./src/unbound* /home/fap/src/
cp ./src/rc.local /etc/
cp ./src/index.html /var/www/html/
cp ./fap.py /home/fap
cp -Rv ./clean /home/fap/
#cp ./status.py /home/fap
cp -Rv ./lib/* /home/fap/lib/
echo "*** X-Bit setzen"
chmod a+x /home/fap/*.sh
chmod a+x /home/fap/src/*.sh
chmod a+x /etc/rc.local

# git update
# echo "*** git clone"
# mkdir /home/fap/template/
# cd /var/www/html
# git clone https://github.com/dfeu/fap
# cd -
# cp /var/www/html/fap/template/* /home/fap/template/
# cp ./src/whitelist_user.conf /var/www/html/fap/

mkdir /home/fap/template/
cp ./template/* /home/fap/template

# Rechte anpassen
echo "*** Rechte in /home/fap anpassen"
chown -R fap:fap /home/fap/*

# Aufräumen
echo "*** Letzte Aufräumarbeiten"
apt-get -y upgrade
apt-get -y autoremove

# sudo 
#echo "*** Anpassung sudo" 
#echo 'www-data ALL=(ALL) NOPASSWD:ALL' | sudo EDITOR='tee -a' visudo


# Finish info ablegen
echo "*** Installation beenden"
touch /home/fap/fap_ready

# That's it...
echo ""
echo "Alles erledigt"
#echo "Jetzt noch bitte einmal neustarten via -sudo reboot-"
echo "Bei Fragen: Prof. Dr. Daniel Spiekermann - daniel.spiekermann@fh-dortmund.de"
echo "10 Sekunden warten für etwaige Prozesse, dann ist ein Neustart möglich"
sleep 10
echo -n "Neustarten j/n? "
read reply

if [ "$reply" = j -o "$reply" = J ]
then
   reboot
else
   echo "Bitte Reboot manuell durchführen"
fi
