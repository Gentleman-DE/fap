**Forensischer Accesspoint -- Installation und Erste Schritte:**

Version 0.8.7

**Was ist das?**

Der forensische Accesspoint (im Folgenden FAP) ist ein auf dem Raspberry
PI basierender, mit einigen Linuxtools ausgestatteter WLAN-Accesspoint,
der mit Hilfe einer Whitelist den Zugriff auf verschiedene
Onlineservices wie Facebook oder WhatsApp ermöglicht und parallel jeden
anderen Zugriff auf das Netzwerk verhindert. Durch Anpassung der
Whitelist ist ein Zugriff auf nahezu jeden Service möglich.

Das Besondere am FAP ist die Möglichkeit, jedes WLAN-fähige Gerät mit
dem Internet zu verbinden und trotzdem gesichert Zugriff auf die
Onlineservices zu erhalten. Durch FAP werden alle Zugriffe auf das
System von Extern (z.B. Find my Phone, Cerbereus, etc.) nach aktuellem
Stand (;-)) unterbunden. Nur der Zugriff auf die freigeschalteten Seiten
ist möglich.

Aufgrund einer gewissen Komplexität ist FAP kein Sachbearbeiterwerkzeug,
sondern setzt Vorkenntnisse aus den Bereichen Kommunikationstechnik,
Netzwerkforensik und Serveradministration voraus. LInuxkenntnisse
schaden darüber hinaus auch nicht.

Der Hauptteil der Administration erfolgt mittlerweile über die
Kommandozeile, die designtechnisch höchstens durchschnittliche
Weboberfläche ist abgekündigt und existiert nur noch aus sentimentalen
Gründen.

**Features:**

- Randomisierte 8-stellige SSID mit dynamischer Passworterstellung
  (SSID=PW)

- Ausleitung aller Netzwerkpakete mittels OVS an separates
  Aufzeichnungssystem (sofern gewünscht)

- DNS-Whitelist inkl IP-Set zum isolierten Zugriff auf vordefinierte
  Services

- Zugriff auf freigeschaltete Seiten ohne Gefahr des Remote-Zugriffs

- Einfacher WLAN-AP Betrieb mit der Möglichkeit zur Aufzeichnung der
  Netzwerkdaten

- Aktualisierung der Templates über GitHub

**Tools:**

hostapd: WLAN-AP Funktionalität

unbound: DNS-Server und DNS-Whitelist

tshark: Extraktion relevanter Daten aus dem Netzwerkstrom

iptables / ipset: Firewallregeln, um IP-basierte Zugriffe zu verhindern.

Lighttpd: Webserver für die Verwaltung per Weboberfläche (deprecated)

Open vSwitch: Port-Mirror für unmittelbare Ausleitung aller
Netzwerkdaten

Munin: Weboberfläche mit Statistiken

Python inkl. diverser Module Komplette Hintergrundverarbeitung

**Installation:**

Die Installation verläuft größtenteils automatisch. Es ist als erstes
notwendig, eine Rasbian Installation auf einem Raspberry PI
durchzuführen. Hierfür wird Rasbian Lite 32 Bit empfohlen. Nach der
Installation sollte einmal sudo raspi-config ausgeführt werden, um das
WLAN-Interface zu aktivieren. Die Ursprungsplanung sah vor, dass eine
zweite NIC installiert sein muss. Die Verkabelung sollte in etwa so
aussehen:

![Ein Bild, das Kabel, Elektronik, Elektrische Leitungen, Elektronisches
Gerät enthält. Automatisch generierte
Beschreibung](media/image1.png){width="3.486111111111111in"
height="2.611111111111111in"}

Die Verbindung zum Internet sollte über den internen RJ45-Port erfolgen.
Die Anbindung des Aufzeichnungssystems sollte über den USB-Adapter
erfolgen. Die Standardeinstellung der Installation sieht mittlerweile
vor, dass dieser Anschluss nicht vorhanden sein muss. Anschließend den
FAP starten und die IP-Adresse auslesen (für Nicht-Netzwerker wird sie
beim Starten mit angezeigt, dann muss man aber einen Monitor
anschließen).

Da Raspberry Pi OS mittlerweile auf die Defaulteinstellung ohne dem User
pi setzt, kann zu Beginn für die Installation eigentlich fast jeder
beliebige Name genutzt werden.

**Die einzige Ausnahme ist fap, da dieser User bei der Installation
durch die Skripte angelegt wird. Dieser Name sollte also NICHT genutzt
werden.**

Die Installation wird mit

sudo ./install.sh

gestartet. Dieses Skript startet den FAP-Installer und legt parallel
eine Log-Datei über die Installation an. Falls dies nicht funktioniert,
müssen mit chmod a+x \*.sh die beiden Installationsskripte ausführbar
gemacht werden

Falls gewünscht, kann die originäre Funktionalität vom FAP wieder
hergestellt werden, so dass ein OVS-Mirror genutzt wird. Hierzu muss in
der fap_setup.sh-Datei die EXPERT-Variable auf 1 gesetzt werden:

EXPERT=1

Hierdurch werden einige Parameter im FAP geändert, so dass die
Aufzeichnung auch **ohne** zweite NIC sauber durchläuft.

Nach der Installation muss der FAP einmal neugestartet werden,
anschließend kann man sich als User fap mit dem Passwort 1234 anmelden
und über die CLI den FAP steuern.

**Übersicht CLI:**

Der FAP wird über CLI administriert. Der Start von FAP erfolgt über

sudo python3 fap.py PARAMETER

Die Parameter sind die folgenden:

<table>
<colgroup>
<col style="width: 13%" />
<col style="width: 16%" />
<col style="width: 50%" />
<col style="width: 19%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Parameter</strong></th>
<th><strong>Werte</strong></th>
<th><strong>Bedeutung</strong></th>
<th><strong>Eingeführt</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>-d</td>
<td></td>
<td>Gesprächigkeit erhöht</td>
<td></td>
</tr>
<tr class="even">
<td>-t</td>
<td>Textdatei mit FQDNs</td>
<td>Zugriff über Templates regeln, welche Templates genutzt werden, wird
über die übergebene Textdatei geregelt (Welche es gibt, zeigt -i)</td>
<td></td>
</tr>
<tr class="odd">
<td>-u</td>
<td>Singuläres Ziel festlegen</td>
<td>Zugriff auf <strong>einen</strong> (!) FQDN beschränken</td>
<td></td>
</tr>
<tr class="even">
<td>-x</td>
<td></td>
<td>FAP in normalen Internetbetrieb versetzen, kein sicherer FAP Betrieb
möglich</td>
<td></td>
</tr>
<tr class="odd">
<td>-s</td>
<td></td>
<td>Statusinformationen abfragen</td>
<td></td>
</tr>
<tr class="even">
<td>-i</td>
<td></td>
<td>Infos über Templates erhalten, kann mit -d kombiniert werden</td>
<td></td>
</tr>
<tr class="odd">
<td>-v</td>
<td></td>
<td>Version anzeigen lassen</td>
<td></td>
</tr>
<tr class="even">
<td>-o</td>
<td>Pfad</td>
<td>Alle anfallenden Netzwerkpakete im pcap-Format in das angegeben
Verzeichnis schreiben</td>
<td>0.8.2</td>
</tr>
<tr class="odd">
<td>-m</td>
<td>Liste von Zielen</td>
<td>FAP nimmt diese (kommaseparierte, ohne Leerzeichen) übermittelte
Liste und ermöglicht den Zugriff auf alle Systeme, die aufgeführt
sind</td>
<td>0.8.5</td>
</tr>
<tr class="even">
<td>-6</td>
<td></td>
<td>IPv6 Funktionalität im Netzwerk prüfen</td>
<td>0.8.7</td>
</tr>
<tr class="odd">
<td>-n</td>
<td></td>
<td>DNS-Fehlfunktion beheben</td>
<td>0.8.7</td>
</tr>
<tr class="even">
<td>--set</td>
<td>SSID:KEY</td>
<td><p>Definieren der bekannten Werte eines Netzwerks. Struktur für die
Übergabe der Werte ist SSID:PSK</p>
<p>Sollte ein Doppelpunkt in der SSID sein, scheitert die
Einstellung</p></td>
<td>0.8.8</td>
</tr>
</tbody>
</table>

**Beispiele:**

Eine Beschränkung auf Whatsapp erfolgt also so:

sudo python3 fap.py -t wa.txt

Eine Beschränkung auf www.polizei-nds.de erfolgt so:

sudo python3 fap.py -u [www.polizei-nds.de](http://www.polizei-nds.de)

Eine Beschränkung auf www.polizei.nrw, [www.web.de](http://www.web.de),
die IP-Adresse 1.1.1.1 erfolgt so:

sudo python3 fap.py -m
[www.polizei.nrw,www.web.de,1.1.1.1](http://www.polizei.nrw,www.web.de,1.1.1.1)

Der Schalter -m kann auch genutzt werden, um nur ein System
freizuschalten, z.B. nur eine IP-Adresse.

Eine Beschränkung auf www.polizei-nds.de und das Kopieren aller
Netzwerkdaten auf einen USB-Stick (gemountet unter /mnt/) erfolgt so:

sudo python3 fap.py -u www.polizei-nds.de -o /mnt/

Während der Aufzeichnung kann durch Drücken einer nahezu beliebigen
Taste eine Übersicht ausgegeben werden, drückt man x, wird die
Aufzeichnung beendet.

**Reset:**

Für Aufräumarbeiten, also wenn der FAP gar nicht mehr benötigt wird,
kann man im Verzeichnis clean das Skript cleaner.sh aufrufen. Dies macht
die meisten Aufrufe des Installers rückgängig, besonders die
OVS-Anpassungen, die manchmal für Irritationen sorgen\...

**Weboberfläche:**

Die Weboberfläche dient nur noch der Darstellung von Munin Statistiken,
und hat ansonsten keinen Mehrwert mehr.

**Nutzung:**

Per CLI die relevanten Services auswählen (Parameter -i, evtl.
kombiniert mit -d), und FAP über -t mitteilen. Dies Einträge werden in
die DNS-White List von Unbound übertragen. Im Hintergrund laufen diverse
*tshark*-Filter, die parallel die relevanten Antwortpakete aus dem
Datenstrom extrahieren.

FAP installiert die relevanten IPs in den zugehörigen *iptables*-Set,
wodurch letztlich der Zugriff auf die Services möglich ist. Falls eine
Seite angefragt werden soll, die nicht in der WL steht, kann diese
manuell in den Templates, oder einer eigenen Templatedate (gespeichert
in /var/www/html/fap/messenger/) hinzugefügt werden. Für diesen Fall
sollte vllt. auch die mapping.txt im gleichen Verzeichnis angepasst
werden.

Die Daten werden entweder mittels OVS-Bridge ausgeleitet, am besten wird
am entsprechenden Anschluss (USB-RJ45-Adapter) ein zusätzliches System
angeschlossen, welches die Daten mittels *tcpdump* o.ä. aufzeichnet,
oder per -o Parameter in ein angegebenes Verzeichnis. Dieses Verzeichnis
sollte sinnvollerweise nicht wirklich auf dem FAP liegen, da niemand
weiß, wie groß die Datenmenge am Ende wirklich ist, die übers Netz
transferiert wird. Für Testzwecke oder auf eigene Gefahr kann dies
jedoch auch lokal erfolgen. Wird der Parameter -o vergessen, erfolgt die
Ausleitung in eine Datei in /var/www/html/.

**Benötigte Hardware:**

- Raspberry PI (nach Möglichkeit \>= Version 3)

- 16 GB MicroSD-Karte

- USB-RJ45-Adapter (zur Ausleitung der Daten) (optional seit v0.8.2)

- Kabel (HDMI, Netzwerkkabel)

**Probleme:**

Probleme kommen immer wieder vor ;-), manchmal hilft es, den FAP per
cleaner-Skript aufzuräumen und neu zu installieren.

Eine einfache Lösungsmöglichkeit besteht darin, mit sudo python3 fap.py
-n die Namensauflösung auf Werkseinstellungen zurückzusetzen.

Falls die Probleme nicht weggehen, kann eine Mail an
<daniel.spiekermann@fh-dortmund.de> geschickt werden.

**Hinweis:**

Ab Version 0.8.7 nutzt der FAP eine UUID, sofern der Parameter -6
genutzt wird. Die UUID taucht in den Logfiles des Servers auf, der zum
Testen genutzt wird, es ist aber keine Zuordnung zu einem speziellen
System möglich. Die UUID dient nur der Statistik, wie viele FAPs über
IPv6 kommunizieren wollen. Daraus kann ermittelt werden, ob weitere
Arbeit in das IPv6-Modul fließen muss.

**Kontakt:**

Prof. Dr. Daniel Spiekermann

FH Dortmund

<daniel.spiekermann@fh-dortmund.de>

fap@spiekermann.it
