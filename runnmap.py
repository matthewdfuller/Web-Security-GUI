#!/usr/bin/python
import os, sys, subprocess
from time import sleep

nmap_args = sys.argv[1]

print nmap_args

proc = subprocess.Popen(["nmap " + nmap_args], stdout=subprocess.PIPE, shell=True)
proc.wait()
(out, err) = proc.communicate()
print "program output:", out