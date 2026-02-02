import os
from termcolor import colored
import datetime
import subprocess
MAPPING_FILE = "/var/www/html/fap/messenger/mapping.txt"


def print_delimiter():
    print("-----------")

def createServiceList(d):
    # Walk through dir and create correct file location
    dir = os.listdir(d)
    for a in dir:
        print(colored("Inhalt der Datei " + str(a), "blue"))
        print(colored("-----------", "blue"))
        datei = str(d) + "/" + str(a)
        # Extract file content
        f = open(datei, "r")
        for i in f:
            print(i, end="")
        print(" ")
        f.close()


def serviceMapping():
    file = open(MAPPING_FILE, "r")
    zuordnung = {}
    for line in file:
        m, n = line.split(":")
        zuordnung[m] = n
    return zuordnung


# Perform acl based on ND
# deprecated!!! since v.0.8.6
def novelty_detection():
    print("Not implemented")


# Return the process id of the given process
def get_pid(name):
    return subprocess.check_output(["pgrep", name])


# Extract PID of a given process name
def find_pid(name):
    p = subprocess.Popen(["pgrep", "-f", name], stdout=subprocess.PIPE)
    m = p.stdout.read()
    return m


# Return the current timestamp in format:2020-09-29 17:19:09.948199
def getTime():
    d = datetime.datetime.now()
    return str(d)


# Return a formatted timestamp
def formatTime(t):
    # Format is as getTime()
    d = t.split()
    beginn = d[0]  # 2020-09-29
    uhrzeit = d[1]
    uhr_aufteilung = uhrzeit.split(":")
    ende = uhr_aufteilung[2].split(".")[0]
    string = beginn + "_" + uhr_aufteilung[0] + "_" + uhr_aufteilung[1] + "_" + ende
    return str(string)
