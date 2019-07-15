#!/usr/bin/env python
# show passive opened connection count

import time
import subprocess
import sys
import traceback

class frame():
    '''
    get original strings
    '''
    
    def __init__(self, name, path=None, outfile=None, title=None):
        self.buffer = None
        self.path = path
        self.name = name
        self.maximum=0
	self.count=0
    
class proc_net_frame(frame):
    def parse(self):
        with open(self.path, 'rb') as f:
       	    self.buffer = f.read()
            self.buffer = self.buffer.splitlines()
        for line in self.buffer:
	    if line.startswith("Tcp: 1"):
		mlist=line.split()

            	out = long(mlist[6])
            	self.count += 1
            	if out > self.maximum:
                    self.maximum = out
        	if self.count >= 100:
                    #sys.stdout.write("\n"+str(self.maximum))
                    sys.stdout.write("\n"+time.strftime("%Y/%m/%d-%H:%M:%S ")+str(self.maximum))
                    self.count=0
                    self.maximum=0
		
		break

class frames():    
    def loop(self):
	target = proc_net_frame("snmp", path="/proc/net/snmp")
        calibration = 0
        while 1:
            time.sleep(0.01-calibration)
            delta = time.time()
            target.parse()
            calibration = time.time() - delta
            if calibration > 0.01:
                calibration =0.01 

if __name__ == '__main__':    
    stat = frames()
    stat.loop()
    
