#!/usr/bin/env python
# use linux command "ss" to monitor all connection to server port "wport" and tcpdump the too long lifetime connection!
import time
import subprocess
import sys

gmax = 100      # threshold time to start recording packets
gtick = 1
wport = 7002    # local service port
pidx = -1
gport = {}      # record connections' existing time
gdebug=1

def cmd_exec(cmd):    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, outerr = process.communicate()
    
    retcode = process.poll()
    return retcode, output, outerr

def exe_async(cmd_line):
    try:
        process = subprocess.Popen(cmd_line, shell=True)
        return 0
    except subprocess.CalledProcessError as e:
        result = e.returncode
    except Exception as e:
        result = -1

    return result
        
class ss_frame():
    def get(self):
        global wport
        _, self.buffer, _ = cmd_exec("ss -tn state established '( dport = :{0} or sport = :{0} )'".format(wport))
        self.buffer = self.buffer.splitlines()

    def finish(self, port, count):
        global gmax
        if count >= gmax:
            print "port survive %d cnt" % count
        
    def notify(self, port, count):
        print "start to tcpdump for {0}/{1}".format(port, count)
        exe_async("tcpdump -i eth0 -B 102400 -p tcp port {0} -w /var/log/socket-{0}.pcap".format(port))

    def parse(self):
        '''
        Recv-Q Send-Q     Local Address:Port  Peer Address:Port
        0      0          127.0.0.1:52090     127.0.0.1:99999
        '''
        global wport,pidx
        start = False
        port = []
        for line in self.buffer:
            if line.startswith("Recv-Q"):
                start = True
                continue
            
            if not start:
                continue
            
            record = line.split()
            if pidx == -1:
                if record[2].split(":")[1] == wport:
                    pidx = 3
                else:
                    pidx = 2

            port += [record[pidx].split(":")[1]]
        
        return port

class frames():
    global gmax, gdebug
    def loop(self, ss):
        global gport,gtick
        try:
            while 1:
                time.sleep(gtick)
                ss.get()
                # port: currently-connected-ports
                port = ss.parse()
                if gdebug > 0:
                    print "port={0}".format(port)

                # nport: new-added-ports, oport: old-disappeared-ports
                nport = [i for i in port if not i in gport.keys()]
                oport = [i for i in gport.keys() if not i in port]

                # handle retaining ports
                for k,v in gport.items():
                    if k in oport:
                        continue
                    gport[k] += 1
                    if gport[k] > gmax:
                        # notify if the connection last too long
                        ss.notify(k, v)

                # handle new ports
                for k in nport:
                    gport[k] = 1

                #callback on old ports
                for k in oport:
                    ss.finish(k, gport[k])
                    del gport[k]

        except Exception as e:
            print("quit as:"+str(e))
        except KeyboardInterrupt:
            print("\nquit now")
        finally:
            print("cleanup successful")
                
#sys.path.insert(0, '/Volumes/case-sensitive/pydevd')
#import pydevd
#pydevd.settrace("192.168.2.168", stdoutToServer=False, stderrToServer=False)

import os
import getopt
if __name__ == '__main__':    
    if os.getuid() != 0:
        print "please use root privilege to run this program, such as 'sudo %s'." % __file__
        sys.exit()
    
    ss = ss_frame()
    stat = frames()
    stat.loop(ss)
    
