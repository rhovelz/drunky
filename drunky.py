#############################################
#!/usr/bin/env python3                      #
#  ___ ___  _ __ ___| |__ (_)_ __   ___     #
# / __/ _ \| '__/ __| '_ \| | '_ \ / _ \    #
#| (_| (_) | |  \__ \ | | | | | | |  __/    #
# \___\___/|_|  |___/_| |_|_|_| |_|\___|    #
#                                           #
#Author: Radivan (Corshine)                 #
#Github: github.com/rdvcorshine/            #
#############################################

import getopt, sys, os, time, _thread, threading, subprocess, datetime, base64
import xml.etree.ElementTree as ET

show_banner = True
target = 0
depth = 1
no_ping = False
output_dir = 'drunky'
extensions = ',php,html,txt,md,sh,py'

helptext = ("""
Drunky: Auto recon ~

Flags:

    -h, --help\t\t\tShow help
    -t, --target IP\t\tTarget ip address
    -o, --output DIR\t\tOutput directory, defaults to "drunky"

""")

full_cmd_arguments = sys.argv
argument_list = full_cmd_arguments[1:]

short_options = "ht:o:vP"
long_options = ["help", "target=", "output="]
verbosity = 0

threads = []

def vprint(v, service, input):
    if v <= verbosity:
        date = datetime.datetime.now().replace(microsecond=0).isoformat()
        print('[%s] %s >> %s' % (date, service, input))

class MThread(threading.Thread):
    def __init__(self, func, arg):
        threading.Thread.__init__(self)
        self.function = func
        self.arguments = arg
    def run(self):
        self.function(**self.arguments)

def run_simple_cmd(cmdstr):
    vprint(4, "drunky", "Running command \"%s\"" % cmdstr)
    return os.popen(cmdstr).read()

def host_up(recursive_level=0):
    if target == 0:
        vprint(0, "drunky", "Invalid target (%s)" % target)
        return False
    if recursive_level > 10:
        vprint(0, "drunky", "Tried 10 times, no result, check if host is up or if it reponds to ping.")
        return False
    if no_ping:
        return True
    r = run_simple_cmd(("nmap -T5 --max-retries=3 -sn %s") % target)
    result = "1 host up" in r
    if result:
        vprint(1, "drunky", "Host is up")
    else:
        vprint(0, "drunky", "Host is not up, does it respond to pings? Retrying in 3seconds")
        time.sleep(3)
        return host_up(recursive_level+1)
    return result

def parse_arugments():
    global target, verbosity, no_ping, depth, wordlist
    try:
        arguments, values = getopt.getopt(argument_list, short_options, long_options)
    except getopt.error as err:
        print(str(err))
        sys.exit(2)

    for current_argument, current_value in arguments:
        if current_argument in ("--verbosity"):
            verbosity = int(current_value)
            vprint(3, "drunky", ("Setting verbosity to %s") % (verbosity))
        elif current_argument in ("-h", "--help"):
            print(helptext)
            sys.exit(1)
        elif current_argument in ("-o", "--output"):
            vprint(3, "drunky", ("Setting output directory (%s)") % (current_value))
            output_dir = current_value
        elif current_argument in ("-t", "--target"):
            vprint(3, "drunky", ("Setting target to %s") % (target))
            target = current_value

def create_result_dir():
    global output_dir
    original_dir = output_dir
    i = 1
    while os.path.isdir(output_dir):
        output_dir = original_dir + "." + str(i)
        i += 1
    os.mkdir(output_dir)
    vprint(2, "drunky", "Set output directory to %s" % output_dir)

def getopenports():
    ports = []
    root = ET.parse('%s/nmap-quickscan.xml' % output_dir).getroot()
    for port in root.findall('./host/ports/port'):
        ports.append(port.attrib['portid'])
    return ports

def getwebports():
    webs = []
    root = ET.parse('%s/nmap-quickscan.xml' % output_dir).getroot()
    for port in root.findall('./host/ports/port'):
        portid = port.attrib['portid']
        services = port.findall('./service');
        if len(services) == 0:
            continue
        for service in services:
            servicename = service.attrib['name']
            if servicename == 'http-proxy': servicename = 'http'
            if servicename == 'https-proxy': servicename = 'https'
            if servicename in ['http', 'https']:
                webs.append({
                    'protocol': servicename,
                    'portid': portid
                })
    return webs


def main():
    global threads
    try:
        if os.geteuid() != 0:
            vprint(0, "drunky", "Drunky requires root privileges, please run as root")
            return

        parse_arugments()

        if show_banner:
            print(base64.b64decode("ICAgX19fX19fICAgICAgICAgICAgICAgIF9fICAgIF8gICAgICAgICAgCiAgLyBfX19fL19fXyAgX19fX19fX19fXy8gL18gIChfKV9fXyAgX19fIAogLyAvICAgLyBfXyBcLyBfX18vIF9fXy8gX18gXC8gLyBfXyBcLyBfIFwKLyAvX19fLyAvXy8gLyAvICAoX18gICkgLyAvIC8gLyAvIC8gLyAgX18vClxfX19fL1xfX19fL18vICAvX19fXy9fLyAvXy9fL18vIC9fL1xfX18vIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgIF9fX18gICAgICAgICAgICAgICAgICAgX18gICAgICAgICAgICAgICAgICAgICAgCiAgIC8gX18gXF9fX19fX18gIF9fX19fXyAgLyAvX19fXyAgX18gIF9fX18gIF9fICBfXwogIC8gLyAvIC8gX19fLyAvIC8gLyBfXyBcLyAvL18vIC8gLyAvIC8gX18gXC8gLyAvIC8KIC8gL18vIC8gLyAgLyAvXy8gLyAvIC8gLyAsPCAvIC9fLyAvIC8gL18vIC8gL18vIC8gCi9fX19fXy9fLyAgIFxfXyxfL18vIC9fL18vfF98XF9fLCAoXykgLl9fXy9cX18sIC8gIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgL19fX18vIC9fLyAgICAvX19fXy8gICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIEJldGEgUmVsZWFzZXMhCgo=").decode("utf-8"))



        vprint(0, "drunky", "Checking whether host is alive...")

        if host_up() == False:
            return

        vprint(0, "drunky", "Starting initial scan...")

        create_result_dir()
        quickscan = run_simple_cmd("nmap -Pn -sS -p- -T5 --min-rate 2500 --max-retries 3 -oN %s/nmap-quickscan.nmap -oX %s/nmap-quickscan.xml %s" % (output_dir, output_dir, target))

        vprint(0, "drunky", "Starting in depth scan...")

        ports = ','.join(str(x) for x in getopenports())
        fullscan = run_simple_cmd("nmap -Pn -O -sV -sC -p%s -T5 --min-rate 2500 --max-retries 3 -oN %s/nmap-fullscan.nmap -oX %s/nmap-fullscan.xml %s" % (ports, output_dir, output_dir, target))

        vprint(0, "drunky", "Starting services scan...\n\n-Full-scans and Quick-scans are done, thank you for using me!!\n-Hope you will get root.")
        while any( t.is_alive() for t in threads ):
            pass
    except KeyboardInterrupt:
        vprint(1, "drunky", "Goodbye")



if __name__ == "__main__":
    main()
