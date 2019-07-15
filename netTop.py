#!/usr/bin/env python
import time
import subprocess
import sys
import traceback
global_conf = {
            "port" : "80",
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
        
LONG_MAX=268435455
import copy
F_LOCAL=2
F_PEER=3
class ss_frame(frame):
    def funcCount(self, map, val):
        try:
            if val.find(".") != -1:
                val = float(val)
            elif val.isdigit():
                val = long(val)
        except:
            pass
        
        max = map.get("max")
        min = map.get("min")
        
        map["count"] += 1
        map["avg"] += val
        if val > max:
            map.update({"max":val})
        if val < min:
            map.update({"min":val})

    def funcGt(self, field, val):
        params = field["params"]
        if len(params) == 0:
            target = field["eq"]
        elif long(val) > params[0]:
            target = field["gt"]
        else:
            target = field["lt"]
        
        return target
        
    def fieldGet(self, key, val):
        return {key: val}
    def fieldGetComma(self, key, val):
        return {key: val.split(",")[0]}
    def fieldGetSlash(self, key, val):
        return {key: val.split("/")[0]}
    def fieldGetSlash2(self, key, val):
        return {key: val.split("/")[1]}
    
    def skmemGet(self, key, val):
        result = {}
        val = val.split("(")[1].split(")")[0].split(",")
        for delimiter,content in zip((1,2,1,2,1,1,1,2),val):
            result[content[:delimiter]] = content[delimiter:]
        return result
    
    def init(self):
        self.cmd = "ss -t4nim state established"
        opts = self.cmd.split("-")[1]
        self.extension = 0
        if opts.find("i") != -1:
            self.extension |= 1
        if opts.find("m") != -1:
            self.extension |= 2
        
        self.fields = {"wscale" : self.fieldGetComma,
                       "rto" : self.fieldGet,
                       "rtt" : self.fieldGetSlash,
                       "ato" : self.fieldGet,
                       "mss" : self.fieldGet,
                       "cwnd" : self.fieldGet,
                       "ssthresh" : self.fieldGet,
                       "retrans" : self.fieldGetSlash2,
                       "rcv_rtt" : self.fieldGet,
                       "rcv_space" : self.fieldGet,
                       "skmem" : self.skmemGet,
                       }
        
                    #State      addr match          field match iter
        self.conf = (
                    {"title":"rto", "func":self.funcGt, "params":[1000], "index":1, "lt":None, "gt":None, "eq":None},
                    {"title":"cwnd", "func":self.funcGt, "params":[], "index":5, "lt":None, "gt":None, "eq":None},
                    {"title":"t", "func":self.funcGt, "params":[], "index":2, "lt":None, "gt":None, "eq":None},
                    {"title":"w", "func":self.funcGt, "params":[], "index":5, "lt":None, "gt":None, "eq":None},
                    {"title":"rtt", "func":self.funcGt, "params":[], "index":2, "lt":None, "gt":None, "eq":None},
                    {"title":"retrans", "func":self.funcGt, "params":[], "index":2, "lt":None, "gt":None, "eq":None},
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
                    targets = ("eq",)
                else:
                    targets = ("lt", "gt")
                
                for t in targets:
                    target = children[t]
                    cc={}
                    if target is None:
                        children.update({t:cc})
                    for stat in ("avg", "count", "min", "max"):
                        if not title:
                            if stat=="avg" and target["count"]:
                                target[stat] /= target["count"]

                            result.append(str(target[stat]))
                            target[stat] = 0
                            if stat=="min":
                                target[stat] = LONG_MAX
                        else:
                            cc.update({stat:0})
                            if stat=="min":
                                cc.update({stat:LONG_MAX})
                            result.append(addr+"."+children["title"]+"."+t+"."+stat)
        
        return result
    
    def get(self):
        _, self.buffer, _ = cmd_exec(self.cmd)    #while [ 1 ];do date >> /var/log/ss.log; ss -4tnm state established '( sport = :80 )' >> /var/log/ss.log; sleep 5;done

    def parse(self):
        self.buffer = self.buffer.splitlines()
        start = False
        record = []
        for line in self.buffer:
            #if line.startswith("State"):
            if line.startswith("Recv-Q"):
                start = True
                continue
            
            if not start:
                continue
            
            mdict = {}
            if self.extension:
                if not line.startswith("\t"):
                    record = line.split()
                    continue
                else:
                    #tbl = self.map.get(record[0])
                    #if tbl is None:
                    #    continue

                    extendRec = line.split()
                    
                    try:
                        for field in extendRec:
                            _field = field.split(":")
                            fieldFunc = self.fields.get(_field[0])
                            if fieldFunc is None:
                                continue
                            mdict.update(fieldFunc(_field[0], _field[1]))
                            
                    except Exception as e:
                        show_backtrace()
                        print str(record)
                        print str(extendRec)
                        raise Exception
            else:
                record = line.split()
                
            #tbl = self.map.get(record[0])
            #if tbl is None:
            #    continue
            #rec = tbl
            rec = self.map.get("ESTAB")
            if record[F_LOCAL].split(":")[1] == global_conf["port"]:
                rec = rec["Local"]
            elif record[F_PEER].split(":")[1] == global_conf["port"]:
                rec = rec["Peer"]
            else:
                continue
            
            if rec is None:
                continue
            
            rec["count"] += 1
            for field in rec["children"]:
                val = mdict.get(field["title"])
                if val is None:
                    val = 0
                target = field["func"](field, val)
                if target:
                    self.funcCount(target, val)
            
        for state in self.states:
            table = table_map.get(self.name + '.' + state)
            if table:
                record = self.walk(self.map[state])
                table.record_handle(record)
                self.tables.append(table)

class conntrack_frame(frame):
    def get(self):
        #_, self.buffer, _ = cmd_exec("conntrack -S")
        #_, self.buffer, _ = cmd_exec("./ctnl.py")
        self.buffer = conntrack()
        
    def prepare(self):
        #_, buffer, _ = cmd_exec("conntrack -S")
        #_, buffer, _ = cmd_exec("./ctnl.py")
        #buffer = buffer.splitlines()
        buffer = conntrack()
        if len(buffer) == 0:    #remove conntrack frame if there hasn't this tool
            index=0
            for i in frame_list:
                if i == self:
                    break
                index += 1
            
            del frame_list[index]
            return
        
        for line in buffer:
            item = line.split()
            name = item[0]
            if line.startswith("cpu="):
                newtbl = table_map["conntrack.cpu"]
                newtbl.name = newtbl.name
                title = []
                for i in item[1:]:
                    title.append(i.split("=")[0])
                newtbl.title_set(title)
                newtbl.out_file = sys.stdout
                break
            
    def parse(self):
        #self.buffer = self.buffer.splitlines()
        result = []
        for line in self.buffer:
            mlist = line.split()
            table = table_map.get(self.name + '.' + mlist[0].split("=")[0])
            if table:
                value = []
                index = 1
                for i in mlist[1:]:
                    value.append(long(i.split("=")[1]))
                if not len(result):
                    result = value
                else:
                    for i in range(len(result)):
                        result[i] += value[i]
                        
        table.record_handle([str(i) for i in result])
        self.tables.append(table)

class tc_frame(frame):
    def get(self):
        _, self.buffer, _ = cmd_exec("tc -s qdisc show dev {0}".format(global_conf["intf"]))

    def parse(self):
        self.buffer = self.buffer.splitlines()
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
                 #tbl     setup_cmd                                                                                                         Chain        match_key
                 ("dSYN", "iptables -t filter -A INPUT  -p tcp -m tcp --dport {0} --tcp-flags SYN,ACK SYN".format(global_conf["port"]),         "INPUT",     "dpt:{0} flags:0x02/0x02".format(global_conf["port"])),
             ("dSYN_ACK", "iptables -t filter -A OUTPUT -p tcp -m tcp --sport {0} --tcp-flags SYN,ACK SYN,ACK".format(global_conf["port"]), "OUTPUT",    "spt:{0} flags:0x12/0x12".format(global_conf["port"])),
                 ("uSYN", "iptables -t filter -A OUTPUT -p tcp -m tcp --dport {0} --tcp-flags SYN,ACK SYN".format(global_conf["port"]),         "OUTPUT",    "dpt:{0} flags:0x02/0x02".format(global_conf["port"])),
             ("uSYN_ACK", "iptables -t filter -A INPUT  -p tcp -m tcp --sport {0} --tcp-flags SYN,ACK SYN,ACK".format(global_conf["port"]), "INPUT",     "spt:{0} flags:0x12/0x12".format(global_conf["port"])),
                 ]
    
    def get(self):
        _, self.buffer, _ = cmd_exec("iptables -vxn -t filter -L ")
        
    def prepare(self):
        for i in self.conf:
            retcode, _, _ = cmd_exec(i[1].replace(" -A ", " -D "))  #remove the old one
            retcode, _, _ = cmd_exec(i[1])
    
    def cleanup(self):
        for i in self.conf:
            retcode, _, _ = cmd_exec(i[1].replace(" -A ", " -D "))  #remove the old one
        
    def parse(self):
        self.buffer = self.buffer.splitlines()
        for line in self.buffer:
            rec = line.split()
            
            if len(rec) == 0 or rec[0] == "pkts":
                continue
            if rec[0] == "Chain":
                chain = rec[1]
                continue
            
            table=None
            for match in self.conf:
                if match[2] == chain and line.find(match[3]) != -1:
                    table = self.name+'.'+match[0]
                    table = table_map.get(table)
                    break;
            
            if table:
                table.record_handle(rec[:2])
                self.tables.append(table)
            
class table():
    def __init__(self, name, out_filter=None, title=None, delta=False):
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
        
    def setup_out_filter(self):
        if self.out_filter is None:
            self.filter_set(self.title)
        
        #filter-out non-exist fields
        self.out_filter = [i for i in self.out_filter if i in self.title]
        
    def title_output(self):
        self.setup_out_filter()
        
        field_name = [self.name+"#"+n for n in self.out_filter]
        self.out_file.write(" ".join(field_name) + " " + self.border)
        
    def title_log(self, log_file):
        field_name = [self.name+"#"+n for n in self.log_filter]
        log_file.write(" ".join(field_name) + " " + self.border)

    def record_output(self):
        self.setup_out_filter()
            
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
             "snmp.Tcp:" : table("Tcp", out_filter=["PassiveOpens","CurrEstab"]),
             "snmp.Udp:" : table("Udp", out_filter=[]),
             "snmp.Ip:" : table("Ip", out_filter=["OutDiscards"]),
             "netstat.TcpExt:" : table("Tcp", out_filter=["ListenDrops"]),
             "netstat.IpExt:" : table("Ip", out_filter=[]),
             "stat.cpu" : table("cpu", title=["user","nice","sys","idle","io","irq","soft","steal","guest","guest_nice"],out_filter=[]),
             "stat.ctxt" : table("ctxt", title=["times"],out_filter=[]),
             "iptable.dSYN" : table("dSYN", title=["pkts","bytes"], out_filter=["pkts"]),
             "iptable.dSYN_ACK" : table("dSYN_ACK", title=["pkts","bytes"], out_filter=["pkts"]),
             "iptable.uSYN" : table("uSYN", title=["pkts","bytes"], out_filter=["pkts"]),
             "iptable.uSYN_ACK" : table("uSYN_ACK", title=["pkts","bytes"], out_filter=["pkts"]),
             "ss.ESTAB" : table("ESTAB", out_filter=["Local.count","Peer.count","Local.cwnd.eq.avg","Peer.cwnd.eq.avg","Local.rto.lt.avg","Local.rto.gt.avg","Peer.rto.lt.avg","Local.w.eq.avg","Peer.w.eq.avg","Local.rtt.eq.avg","Peer.rtt.eq.avg"], delta=False),
             "tc" : table("tc", title=["s_bytes","s_pkts","dropped","overlimits","requeues","b_bytes","b_pkts"], out_filter=["dropped"]),
             "dev.Eth" : table("dev", out_filter=["r_drop","t_drop"], title=["r_byte","r_pkt","r_err","r_drop","r_fifo","r_frame","r_comp","r_multi","t_byte","t_pkt","t_err","t_drop","t_fifo","t_colls","t_carr","t_comp"]),
             "conntrack.cpu" : table("ct", out_filter=["drop","early_drop","error","insert_failed","invalid"],),
             }

    frame_list = [
              proc_net_frame("snmp", path="/proc/net/snmp"),
              proc_net_frame("netstat", path="/proc/net/netstat"),
              proc_net_dev_frame("dev", path="/proc/net/dev"),
              proc_stat_frame("stat", path="/proc/stat"),
              tc_frame("tc"),
              conntrack_frame("conntrack"),
              iptable_frame("iptable"),
              ss_frame("ss"),
              ]

    #remove unnecessary frame in frame_list through table_map
    _frame_list = []
    for f in frame_list:
        found = False
        for t in table_map.keys():
            t = t.split('.')[0]
            if t == f.name:
                found = True
                break
        
        if found:
            _frame_list.append(f)
        else:
            print "remove frame[{0}]".format(f.name)
    
    frame_list = _frame_list
            
def doAlarm():
    global global_conf
    exe_async("date >> /var/log/ss.log; ss -4tnmi state established '( sport = :{0} )' >> /var/log/ss.log".format(global_conf["port"]))

def show_backtrace():    
    traceback.print_exc()

def iter(mylist, callback):
    count = len(mylist)
    i = 0
    while i < count:
        f = mylist[i]
        callback(f)
        i+=1
        if len(mylist) < count:
            # indicate this frame del itself from list
            i-=1
            count-=1

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
            pass#self.log_file.write("\n==>start at (per {0} second) [{1}]\n".format(self.delta, time.asctime()))
        
    def prepare(self):
        # use this iterator to handle deleting element correctly
        iter(frame_list, lambda f: f.prepare())
#         for f in frame_list:
#             f.prepare()
    
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
            calibration = 0
            while 1:
                time.sleep(self.delta-calibration)
                
                #use time.clock() to calculate CPU time of this program, use time.time() to calculate wall time elapse of this program
                #delta = time.clock()
                delta = time.time()
                
                self.output_newline(time.strftime("%Y/%m/%d-%H:%M:%S "))
                #self.output_newline("("+str(calibration)+")"+time.strftime("%Y/%m/%d-%H:%M:%S "))
                self.get()
                self.parse()
                self.output()
                #self.task()
                
                #result = time.clock() - delta
                calibration = time.time() - delta
                if calibration > self.delta:
                    calibration = self.delta
                
        except Exception as e:
            print("quit as:"+str(e))
            show_backtrace()
        except KeyboardInterrupt:
            print("\nquit now")
        finally:
            if self.log_file:
                self.log_file.close()
            self.cleanup()
            print("cleanup successful")
        
    def task(self):
        doAlarm()
        
'''
conntrack implemented by python (original content of the file "ctnl.py") and be used instead of linux tools "conntrack"
'''
import os
import socket
import struct

NLMSG_NOOP = 1
NLMSG_ERROR = 2
NLMSG_DONE = 3

NETLINK_NETFILTER=12
NFNETLINK_V0=0

NFNL_SUBSYS_CTNETLINK=1
IPCTNL_MSG_CT_GET_STATS_CPU=4

NLM_F_REQUEST=1
NLM_F_ROOT=0x100
NLM_F_MATCH=0x200
NLM_F_DUMP=NLM_F_ROOT|NLM_F_MATCH

class ctnl:
    MSGLEN=0
    MSGTYPE=1
    def __init__(self, next=None):
        self.length = 4*4
        self.pattern = "IHHII"
        self.nlFlags = NLM_F_REQUEST | NLM_F_DUMP
        self.nlSeq = 7
        self.nlPid = 0
        self.next = next
        self.nlSocket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        self.nlSocket.bind((os.getpid(), 0))
        #print self.nlSocket.getsockname()
    
    def send(self, subsys, type, content=None):
        self.nlType = subsys<<8 | type
        self.payload = self.next.send(content)
        self.nlHdr = struct.pack(self.pattern, len(self.payload) + self.length, self.nlType, self.nlFlags, self.nlSeq, self.nlPid)
        
        self.nlSocket.send(self.nlHdr + self.payload)
    
    def recv(self):
        output = []
        while True:
            data = self.nlSocket.recv(65535)
            while len(data):
                nlHdr = struct.unpack(self.pattern, data[:self.length])
                if nlHdr[ctnl.MSGTYPE]==NLMSG_NOOP:
                    print "no-op"
                    continue
                elif nlHdr[ctnl.MSGTYPE]==NLMSG_ERROR:
                    errno = -struct.unpack("i", data[self.length:self.length+4])[0]
                    print os.strerror(errno)
                    break
                elif nlHdr[ctnl.MSGTYPE]==NLMSG_DONE:
                    #print "Done."
                    return output
                
                #print "ctnl:"+str(nlHdr)
                output.append(self.next.recv(data[self.length:nlHdr[ctnl.MSGLEN]]))
                data = data[nlHdr[ctnl.MSGLEN]:]
        
        return output
    
    def loop(self):
        '''
        return 'list' of records
        '''
        self.send(NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET_STATS_CPU)
        output = self.recv()
        #return '\n'.join(output)
        return output
            
class genl:
    RESID=2
    def __init__(self, res_id=0, version = 0):
        self.map = ["cpu=", "searched=", "found=", "new=", "invalid=", "ignore=", "delete=", "delete_list=", "insert=", "insert_failed=", "drop=", "early_drop=", "error=", "search_restart="]
        self.pattern = "!BBH"
        self.length = 4
        self.family = socket.AF_INET
        self.version = NFNETLINK_V0
        self.res_id = 0
    def send(self, content=None):
        return struct.pack(self.pattern, self.family, self.version, self.res_id)

    def recv(self, data):
        geHdr = struct.unpack(self.pattern, data[:self.length])
        #print "genl:"+str(geHdr)
        #print "cpu"+str(geHdr[genl.RESID])+":"
        self.res_id = geHdr[genl.RESID]
        self.attributes = self.parseAttributes(data[self.length:])
        #print "attributes:"+str(self.attributes)
        output = "cpu="+str(self.res_id) + "\t" + " ".join([self.map[i]+str(self.attributes[i][0]) for i in range(1,1+len(self.attributes))])
        #print output
        return output
    
    def parseAttributes(self, data):
        attrs = {}
        while len(data):
            attr_len, attr_type = struct.unpack("HH", data[:4])
            attrs[attr_type] = struct.unpack("!I", data[4:attr_len])
            attr_len = ((attr_len + 4 - 1) & ~3)
            data = data[attr_len:]
        return attrs

def conntrack():
    '''
    return 'list' of records each of which is a line string
    '''
    s = ctnl(genl())
    return s.loop()

'''
main entry
'''

#sys.path.insert(0, '/Volumes/case-sensitive/pydevd')
#import pydevd
#pydevd.settrace("192.168.2.128", stdoutToServer=False, stderrToServer=False)

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
    
