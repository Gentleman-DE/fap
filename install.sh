#!/bin/bash
#
# Installiert den FAP und protokolliert die Ausgabe für eine Problemanalyse
# Kontakt:  daniel.spiekermann@fh-dortmund.de
#           faplspiekermann.it
#
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi
./fap_setup.sh | tee fap-setup_log.txt
