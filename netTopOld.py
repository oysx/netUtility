#!/usr/bin/env python
import time
import subprocess
import sys

global_conf = {
            "port" : "8000",
            "logfile" : "/var/log/netTop.log",
            "delta" : 1,
            "intf" : "eth0",
            }

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

class frame():
    '''
    get original strings
    '''
    
    def __init__(self, name, path=None, outfile=None, title=None):
        self.buffer = None
        self.path = path
        self.outfile = outfile
        self.name = name
        
        self.title = title
        self.tables = []
        self.init()
    
    def init(self):
        pass
    
    def prepare(self):
        pass
    
    def cleanup(self):
        pass
    
    def get(self):
        if self.path:
            with open(self.path, 'rb') as f:
                self.buffer = f.read()
                self.buffer = self.buffer.splitlines()
    
    def parse(self):
        '''
        parse string in buffer onto "tables" list
        '''
        pass
    
    def title_output(self, log_file=None):
        for t in self.tables:
            t.title_output()
            if log_file:
                t.title_log(log_file)
        
    def output(self, log_file=None):
        for t in self.tables:
            t.record_output()
            if log_file:
                t.record_log(log_file)

class proc_net_frame(frame):
    def parse(self):
        index = 0
        for line in self.buffer:
            mlist = line.split()
            table = table_map.get(self.name + '.' + mlist[0])
            if table:
                if index % 2:
                    table.record_handle(mlist[1:])
                    self.tables.append(table)
                else:
                    table.title_set(mlist[1:])
            
            index += 1

import copy
class proc_stat_frame(frame):
    def prepare(self):
        _, buffer, _ = cmd_exec("cat /proc/stat")
        buffer = buffer.splitlines()
        for line in buffer:
            name = line.split()[0]
            if line.startswith("cpu") and name != "cpu":
                newtbl = copy.deepcopy(table_map["stat.cpu"])
                newtbl.name = name
                newtbl.out_file = sys.stdout
                table_map["stat."+name] = newtbl
    def parse(self):
        for line in self.buffer:
            mlist = line.split()
            table = table_map.get(self.name + '.' + mlist[0])
            if table:
                table.record_handle(mlist[1:])
                self.tables.append(table)
        
import copy    
class ss_frame(frame):
    def funcCount(self, map, val):
        max = map.get("max")
        min = map.get("min")
        count = map.get("count")
        
        map.update({"count":count+1})
        if val > max:
            map.update({"max":val})
        if val < min:
            map.update({"min":val})

    def funcGt(self, field, val):
        params = field["params"]
        if len(params) == 0:
            target = field["eg"]
        elif val > params[0]:
            target = field["gt"]
        else:
            target = field["lt"]
        
        return target
        
    def init(self):
                    #State      addr match          field match iter
        self.conf = (
                    #{"title":"rto", "func":self.funcGt, "params":[100], "index":-1, "lt":None, "gt":None, "eq":None},
                    )

        self.states = ("ESTAB",)
        self.skeleton = {"State": {
                                "Local" : {
                                            "count" : 0,
                                            "children" : None,
                                            },
                                 "Peer" : {
                                            "count" : 0,
                                            "children" : None
                                            },
                                },
                     }
        self.map = {}
        self.title = []
        for i in self.states:
            state = copy.deepcopy(self.skeleton["State"])
            self.map.update({i:state})
            for addr in state.values():
                addr.update({"children" : copy.deepcopy(self.conf)})
                
            self.title = self.walk(state, title=True)
    
            table = table_map.get(self.name + '.' + i)
            if table:
                table.title_set(self.title)

    def walk(self, state, title=False):
        result = []
        for addr in ("Local","Peer"):
            if not title:
                result.append(str(state[addr]["count"]))
                state[addr]["count"] = 0    #clear after read
            else:
                result.append(addr+".count")
            for children in state[addr]["children"]:
                if len(children["params"]) == 0:
                    targets = ("eq")
                else:
                    targets = ("lt", "gt")
                
                for t in targets:
                    target = children[t]
                    cc={}
                    if target is None:
                        children.update({t:cc})
                    for stat in ("count", "min", "max"):
                        if not title:
                            result.append(str(target[stat]))
                            target[stat] = 0
                        else:
                            cc.update({stat:0})
                            result.append(addr+"."+children["title"]+"."+t+"."+stat)
        
        return result
    
    def get(self):
        _, self.buffer, _ = cmd_exec("ss -t4ns")    #while [ 1 ];do date >> /var/log/ss.log; ss -4tnm state established '( sport = :80 )' >> /var/log/ss.log; sleep 5;done
        self.buffer = self.buffer.splitlines()

    def parse(self):
        start = False
        for line in self.buffer:
            if line.startswith("State"):
                start = True
                continue
            
            if not start:
                continue
            
            record = line.split()
            tbl = self.map.get(record[0])
            if tbl is None:
                continue
            rec = tbl
            if record[3].split(":")[1] == global_conf["port"]:
                rec = rec["Local"]
            elif record[4].split(":")[1] == global_conf["port"]:
                rec = rec["Peer"]
            else:
                continue
            
            if rec is None:
                continue
            
            rec["count"] += 1
            for field in rec["children"]:
                val = record[field["index"]]
                target = field["func"](self, field, val)
                self.funcCount(target, val)
            
        for state in self.states:
            table = table_map.get(self.name + '.' + state)
            if table:
                record = self.walk(self.map[state])
                table.record_handle(record)
                self.tables.append(table)

class conntrack_frame(frame):
    def get(self):
        _, self.buffer, _ = cmd_exec("conntrack -S")
        self.buffer = self.buffer.splitlines()

    def prepare(self):
        _, buffer, _ = cmd_exec("conntrack -S")
        buffer = buffer.splitlines()
        for line in buffer:
            item = line.split()
            name = item[0]
            if line.startswith("cpu="):
                newtbl = copy.deepcopy(table_map["conntrack.cpu=0"])
                newtbl.name = "conntrack."+name
                title = []
                for i in item[1:]:
                    title.append(i.split("=")[0])
                newtbl.title_set(title)
                newtbl.out_filter = ["drop","early_drop"]
                newtbl.out_file = sys.stdout
                table_map["conntrack."+name] = newtbl
    
    def parse(self):
        for line in self.buffer:
            mlist = line.split()
            table = table_map.get(self.name + '.' + mlist[0])
            if table:
                value = []
                for i in mlist[1:]:
                    value.append(i.split("=")[1])
                table.record_handle(value)
                self.tables.append(table)

class tc_frame(frame):
    def get(self):
        _, self.buffer, _ = cmd_exec("tc -s qdisc show dev {0}".format(global_conf["intf"]))
        self.buffer = self.buffer.splitlines()

    def parse(self):
        content=["","","","","","",""]
        for line in self.buffer:
            if line.startswith("qdisc"):
                continue
            
            rec = line.split()
            if rec[0]=="Sent":
                content[0] = rec[1]
                content[1] = rec[3]
                content[2] = rec[6].replace(",","")
                content[3] = rec[8]
                content[4] = rec[10].replace(")","")
            elif rec[0]=="backlog":
                content[5] = rec[1].replace("b","")
                content[6] = rec[2].replace("p","")
                
        table = table_map.get(self.name)
        if table:
            table.record_handle(content)
            self.tables.append(table)

class proc_net_dev_frame(frame):
    def init(self):
                    #tbl    match_key
        self.conf = ("Eth", "{0}:".format(global_conf["intf"]))
    
    def parse(self):
        for line in self.buffer:
            if line.find("|") != -1:
                continue
            
            if line.find(self.conf[1]) == -1:
                continue
            
            table = table_map.get(self.name + '.' + self.conf[0])
            if table:
                table.record_handle(line.split()[1:])
                self.tables.append(table)

class iptable_frame(frame):
    def init(self):
        self.conf = [
                 #tbl    setup_cmd                                                                    match_key
                 ("SYN", "iptables -t filter -A INPUT -p tcp -m tcp --dport {0} --tcp-flags SYN SYN".format(global_conf["port"]), "SYN"),
                 ("ECN", "iptables -t filter -A INPUT -p tcp -m tcp --dport {0} -m ecn --ecn-ip-ect 3".format(global_conf["port"]), "ECN"),
                 ]
    
    def get(self):
        _, self.buffer, _ = cmd_exec("iptables -vx -t filter -L ")
        self.buffer = self.buffer.splitlines()
        
    def prepare(self):
        for i in self.conf:
            retcode, _, _ = cmd_exec(i[1].replace(" -A ", " -D "))  #remove the old one
            retcode, _, _ = cmd_exec(i[1])
    
    def cleanup(self):
        for i in self.conf:
            retcode, _, _ = cmd_exec(i[1].replace(" -A ", " -D "))  #remove the old one
        
    def parse(self):
        for line in self.buffer:
            if line.startswith("Chain") or line.startswith("    pkts"):
                continue
            table=None
            for match in self.conf:
                if line.find(match[2]) != -1:
                    table = self.name+'.'+match[0]
                    table = table_map.get(table)
                    break;
            
            if table:
                table.record_handle(line.split()[:2])
                self.tables.append(table)
            
class table():
    def __init__(self, name, out_filter=None, title=None, delta=True):
        self.title = title
        self.out_filter = out_filter
        self.log_filter = title
        #self.log_filter = out_filter
        self.name = name
        self.out_file = sys.stdout
        self.border = ""    #"# "
        self.delta = delta
        
        self.record_last = []
        self.record_delta = []
        
    def title_set(self, title):
        self.title = title
        self.log_filter = title
        
    def filter_set(self, out_filter):
        self.out_filter = out_filter
        #self.log_filter = out_filter
        
    def record_handle(self, record):
        if self.delta:
            self.record_delta = []
            for i in range(len(record)):
                if not len(self.record_last):
                    self.record_delta.append(long(record[i]))
                else:
                    self.record_delta.append(long(record[i]) - long(self.record_last[i]))
        
        self.record_last = record
        
    def title_output(self):
        if not self.out_filter:
            self.filter_set(self.title)
        field_name = [self.name+"#"+n for n in self.out_filter]
        self.out_file.write(" ".join(field_name) + " " + self.border)
        
    def title_log(self, log_file):
        field_name = [self.name+"#"+n for n in self.log_filter]
        log_file.write(" ".join(field_name) + " " + self.border)

    def record_output(self):
        if not self.out_filter:
            self.filter_set(self.title)
            
        out = ""
        for i in self.out_filter:
            index = self.title.index(i)
            out += self.record_last[index]
            if self.delta:
                out += "(" + str(self.record_delta[index]) + ")"
            out += " "
        self.out_file.write(out + self.border)
    
    def record_log(self, log_file):
        out = ""
        for i in self.log_filter:
            index = self.title.index(i)
            out += self.record_last[index] + " "
        log_file.write(out + self.border)
        
table_map = {}
frame_list = []
def init_conf():
    global table_map,frame_list
    table_map = {
             "snmp.Tcp:" : table("Tcp", out_filter=["PassiveOpens"]),
             "snmp.Udp:" : table("Udp", out_filter=["OutDatagrams"]),
             "snmp.Ip:" : table("Ip", out_filter=["OutDiscards","OutNoRoutes"]),
             "netstat.TcpExt:" : table("Tcp", out_filter=["ListenOverflows", "ListenDrops"]),
             "netstat.IpExt:" : table("Ip", out_filter=["OutOctets"]),
             #"stat.cpu" : table("cpu", title=["user","nice","sys","idle","io","irq","soft","steal","guest","guest_nice"],out_filter=["idle"]),
             #"stat.ctxt" : table("ctxt", title=["times"],out_filter=["times"]),
             "iptable.SYN" : table("SYN", title=["pkts","bytes"], out_filter=["pkts"]),
             #"iptable.ECN" : table("ECN", title=["pkts","bytes"], out_filter=["pkts"]),
             "ss.ESTAB" : table("ESTAB", out_filter=[], delta=False),
             #"tc" : table("tc", title=["s-bytes","s-pkts","dropped","overlimits","requeues","b-bytes","b-pkts"], out_filter=["dropped","s-bytes"]),
             #"dev.Eth" : table("dev", out_filter=["r-byte","r-err","r-drop","t-byte","t-err","t-drop"], title=["r-byte","r-pkt","r-err","r-drop","r-fifo","r-frame","r-comp","r-multi","t-byte","t-pkt","t-err","t-drop","t-fifo","t-colls","t-carr","t-comp"]),
             "conntrack.cpu=0" : table("cpu=0", out_filter=[],),
             }

    frame_list = [
              proc_net_frame("snmp", path="/proc/net/snmp"),
              proc_net_frame("netstat", path="/proc/net/netstat"),
              iptable_frame("iptable"),
              ss_frame("ss"),
              proc_net_dev_frame("dev", path="/proc/net/dev"),
              #proc_stat_frame("stat", path="/proc/stat"),
              tc_frame("tc"),
              conntrack_frame("conntrack"),
              ]

def doAlarm():
    global global_conf
    exe_async("date >> /var/log/ss.log; ss -4tnmi state established '( sport = :{0} )' >> /var/log/ss.log".format(global_conf["port"]))

class frames():    
    def __init__(self):
        self.alarm = 0
        self.threshold = 0
        self.log_file = None
        log_filename = global_conf["logfile"]
        if log_filename:
            self.log_file = open(log_filename, "a+")
        self.delta = global_conf["delta"]
        print("log file at {0}".format(str(log_filename)))
        if self.log_file:
            self.log_file.write("\n==>start at (per {0} second) [{1}]\n".format(self.delta, time.asctime()))
        
    def prepare(self):
        for f in frame_list:
            f.prepare()
    
    def cleanup(self):
        for f in frame_list:
            f.cleanup()
            
    def get(self):
        for f in frame_list:
            f.get()
    
    def parse(self):
        for f in frame_list:
            f.tables = []
            f.parse()
    
    def output_title(self):
        self.get()
        self.parse()
        self.output_newline("time ")
        for f in frame_list:
            f.title_output(self.log_file)
    
    def output(self):
        for f in frame_list:
            f.output(self.log_file)
    
    def output_newline(self, appender=""):
        sys.stdout.write("\n"+appender)
        if self.log_file:
            self.log_file.write("\n"+appender)
    
    def loop(self):
        try:
            while 1:
                time.sleep(self.delta)
                self.output_newline(time.strftime("%Y/%m/%d-%H:%M:%S "))
                self.get()
                self.parse()
                self.output()
                self.task()
        except Exception as e:
            print("quit as:"+str(e))
        except KeyboardInterrupt:
            print("\nquit now")
        finally:
            if self.log_file:
                self.log_file.close()
            self.cleanup()
            print("cleanup successful")
        
    def task(self):
        #exe_async("date >> /var/log/ss.log; conntrack -S >> /var/log/ss.log; conntrack -C >> /var/log/ss.log")
        tbl =table_map.get("snmp.Tcp:")
        if not tbl:
            return
        threshold = tbl.record_delta[tbl.title.index("PassiveOpens")]
        self.alarm += 1
        self.threshold += threshold
        if self.alarm >= 5:
            self.alarm = 0
            if self.threshold <= 250:
                doAlarm()
            self.threshold = 0
        
#sys.path.insert(0, '/Volumes/case-sensitive/pydevd')
#import pydevd
#pydevd.settrace("192.168.2.168", stdoutToServer=False, stderrToServer=False)

import os
import getopt
if __name__ == '__main__':    
    if os.getuid() != 0:
        print "please use root privilege to run this program, such as 'sudo %s'." % __file__
        sys.exit()
        
    try:
        options, args = getopt.getopt(sys.argv[1:], "t:f:p:i:", ["time", "file", "port", "interface"])
    except getopt.GetoptError:
        sys.exit()
    
    for k,v in options:
        if k in ("-t","--time"):
            global_conf["delta"] = long(v)
        if k in ("-f","--file"):
            global_conf["logfile"] = v
        if k in ("-p","--port"):
            global_conf["port"] = long(v)
        if k in ("-i","--interface"):
            global_conf["intf"] = v
    
    init_conf()
    stat = frames()
    stat.prepare()
    stat.output_title()
    stat.loop()
    
