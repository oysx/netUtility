#!/usr/bin/env python

import time
import subprocess
import sys
import os
import getopt
from copy import deepcopy

LONG_MAX="268435455"

global_conf={
	"other":False,
	"raw":False,
	}

def shortFloat(val):
	if val.find(".") != -1:
		val=val.split(".")[0] + "." + val.split(".")[1][:2]
	return val

columnWidths = []
def format(mlist,length=12):
	result = ""
	for i in mlist:
		i=shortFloat(i)
		result += i+" "*(length-len(i))
	return result

def doFormat(mlist):
	global columnWidths
	result = ""
	for i in range(len(mlist)):
		val=shortFloat(mlist[i])
		result += val+" "*(2+columnWidths[i]-len(val))
	return result

def guessFormat(mlist, length=12):
	global columnWidths
	if not len(columnWidths):
		columnWidths = [0 for i in mlist]
	
	for i in range(len(mlist)):
		val=shortFloat(mlist[i])
		if len(val) > columnWidths[i]:
			columnWidths[i] = len(val)

def getBracket(v, orig=False):
	if v.find("(") != -1:
		if orig==True:
			v=v.split("(")
			return v[0]

		v=v.split("(")
		v=v[1].split(")")
		return v[0]
	else:
		return v

def packMap(title, line, params, evaluate=False):
		global global_conf
		map = params["data"]
		for i in title[1:]:
			if global_conf["raw"]:
				#don't hide the non-changed fields
				params["result"].update({i:"more"})
				continue
			
			index = title.index(i)
			if map.get(i):
				if map[i] == line[index]:
					continue
				else:
					params["result"].update({i:"more"})
			else:
				map.update({i : line[index]})

def packReduce(params):
		if type(params["result"]) is dict:
			result = []
			for i in params["result"]:
				result.append(i)
			result.sort()
			params["result"] = result

def inList(title, filter, line):
	result = []
	for i in filter:
		result.append(line[title.index(i)])
		
	return result

def toNumber(val, title=""):
	if val.find(".") != -1:
		return float(val)
	if val.find("K") != -1:
		val = val.replace("K","000")
	return long(val)

def rateMap(title, line, params, evaluate=False):
	global generatedField
	
	rateFilterOut = params["rateFilterOut"]
	#support wildcard
	for i in rateFilterOut:
		if i.endswith("*"):
			match = rateFilterOut.pop(rateFilterOut.index(i))
			match = match.split("*")[0]
			for j in title:
				if j.startswith(match):
					rateFilterOut += [j]

	showFilter = params["showFilter"]

	#filterout non-exist fields
	#showFilter = [i for i in showFilter if i in title]

	titleShow = showFilter + [i[0]+i[1]+i[2] for i in generatedField]
	if params["first"]==True:
		params["first"]=False
		if not evaluate:
			print title[0]+" "+" ".join(titleShow)
		for i in range(len(title)):
			if line[i]==LONG_MAX:
				line[i]="0"
			if title[i] not in rateFilterOut:
				params["result"].append(toNumber(line[i]))
			else:
				params["result"].append(line[i])
	else:
		prevLine = params["result"][0]
		origLine = deepcopy(line)
		for i in range(len(line)):
			if line[i]==LONG_MAX:
				line[i]="0"
			if title[i] not in rateFilterOut:
				newone=toNumber(line[i],title[i])
				delta=newone-params["result"][i]
				if params["pattern"]:
					line[i]=str(delta)
				else:
					line[i]=line[i]+"("+str(delta)+")"
				params["result"][i]=newone
			else:
				params["result"][i]=line[i]
		for colCmd in columnCmd:
			colCmd["func"](title, line, origLine)
				
		data = inList(title, showFilter, line)
		data += [i[3] for i in generatedField]
		if evaluate:
			guessFormat(data)
		else:
			if len(title) != len(line):
				print "[ERROR]"
				return
			
			#check time skip
			prevLineTime = time.strptime(prevLine, "%Y/%m/%d-%H:%M:%S")
			curLineTime = time.strptime(line[0], "%Y/%m/%d-%H:%M:%S")
			prevLineTime = time.mktime(prevLineTime)
			curLineTime = time.mktime(curLineTime)
			for i in range(long(curLineTime-prevLineTime-1)):
				print "[BLANK]"
			print line[0]+" "+doFormat(data)

def top(title, line, origLine):
        global topTitle
        rang=range(12)
        rang.append("")
        for i in rang:
                prefix="cpu"+str(i)+"#"
                if prefix+"idle" in title:
                        total = 0
                        for name in ["user","nice","sys","idle","io","irq","soft","steal","guest","guest_nice"]:
                                index = title.index(prefix+name)
                                total += long(line[index])
                        for name in ["user","nice","sys","idle","io","irq","soft","steal","guest","guest_nice"]:
                                index = title.index(prefix+name)
                                line[index] = str((long(line[index]) * 100) / total)

def B2b(title, line, origLine):
	for i in ["tc#s_bytes","dev#t_byte","dev#r_byte","Ip#InOctets","Ip#OutOctets"]:
		try:
			index = title.index(i)
			value = long(line[index])
			line[index] = str((value*8)/1000000)+"Mbps"
		except ValueError:
			#bypass non exist fields
			pass
		
def rtt2ms(title, line, origLine):
	for i in title:
		if i.startswith("ESTAB#") and i.find(".rtt.")!=-1:
			index = title.index(i)
			value = float(line[index])
			line[index] = str((value*8))
	
generatedField = [
			["ct#new","-","ct#delete",None,False],
			]
def calculate(title, line, origLine):
	global generatedField
	for i in generatedField:
		data = line if i[4] else origLine
		
		if not i[0] in title:
			i[3] = "None"
			continue
		
		left = title.index(i[0])
		left = data[left]
		right = title.index(i[2])
		right = data[right]
		i[3] = str(eval(left+i[1]+right))
		
command = {
	"pack" : {"map":packMap, "result":{}, "reduce":packReduce, "data":{}},
	"rate" : {"map":rateMap, "result":[], "showFilter":[], "rateFilterOut":["time","Tcp#CurrEstab","ESTAB#*","tc#b_bytes", "tc#b_pkts"],"pattern":True,"first":True},
	}
columnCmd = [
			{"func":top},
			{"func":B2b},
			{"func":calculate},
			{"func":rtt2ms}
			]

def goThrough(filename, cmd, evaluate=False):
	with open(filename, 'rb') as f:
		index = 0
		while 1:
			line = f.readline()
			if line == "":
				break
			if line == "\n":
				continue
			mlist = line.split()
			if not index:
				title = mlist
			else:
				func = command.get(cmd)
				if func:
					command[cmd]["map"](title, mlist, command[cmd], evaluate)
			index += 1

def checkLogFile(filename):
	with open(filename, 'rb') as f:
		count = 0
		while 1:
			line = f.readline()
			if line == "":
				break
			if line.startswith("time"):
				count += 1
		if count > 1:
			print "multiple running results ({0}) found in the log file {1}, currently we can not support it. Pls edit the log file and left only once".format(count, filename)
			return False
	
	return True

def main(filename):
	global command,global_conf,columnWidths

	#not support multiple results, check it
	if not checkLogFile(filename):
		return
	
	#pack result
	goThrough(filename, "pack")
	command["pack"]["reduce"](command["pack"])
	
	#filter result
	dropFilter = ["ct#drop", "ct#early_drop", "tc#dropped", "tc#overlimits", "dev#t_drop", "dev#r_drop", "Tcp#ListenDrops", "Tcp#TCPPrequeueDropped", "Tcp#TCPBacklogDrop", "Tcp#TCPMinTTLDrop", "Tcp#TCPDeferAcceptDrop", "Tcp#TCPReqQFullDrop", "Tcp#TCPOFODrop", "Tcp#TCPSACKDiscard","Ip#InDiscards","Ip#OutDiscards"]
	errorFilter = ["ct#error","ct#insert_failed","ct#invalid","dev#t_err","dev#r_err","Ip#InCsumErrors","Ip#InTruncatedPkts","Ip#InNoRoutes","Tcp#TCPFastOpenListenOverflow","Tcp#TCPTimeWaitOverflow","Tcp#TCPFastOpenPassiveFail"]
	tcpFilter = ["Tcp#PassiveOpens", "Tcp#ActiveOpens", "Tcp#CurrEstab", "Tcp#TCPMemoryPressures","Tcp#TCPTimeouts","Tcp#TCPSpuriousRTOs","Tcp#TCPRetransFail","Tcp#BusyPollRxPackets","Tcp#TCPSpuriousRtxHostQueues","Tcp#RetransSegs","Tcp#EstabResets","Tcp#OutRsts"]
	ssFilter = ["ESTAB#Peer.rtt.eq.avg","ESTAB#Local.rtt.eq.avg","ESTAB#Peer.cwnd.eq.avg","ESTAB#Local.cwnd.eq.avg","ESTAB#Peer.rto.lt.avg","ESTAB#Peer.rto.gt.avg","ESTAB#Local.rto.lt.avg","ESTAB#Local.rto.gt.avg","ESTAB#Peer.retrans.eq.avg","ESTAB#Local.retrans.eq.avg","ESTAB#Peer.w.eq.avg", "ESTAB#Local.w.eq.avg","ESTAB#Peer.r.eq.avg","ESTAB#Local.r.eq.avg","ESTAB#Peer.count","ESTAB#Local.count"]
	iptFilter = ["dSYN#pkts","uSYN_ACK#pkts","dSYN_ACK#pkts","uSYN#pkts"]
	throughputFilter = ["tc#b_bytes","tc#s_bytes","dev#t_byte","dev#r_byte","Ip#OutOctets","Ip#InOctets"]
	bufferFilter = ["tc#requeues","tc#overlimits","tc#b_pkts"]
	topFilter = ["cpu#idle"]
	
	allFilter = dropFilter+errorFilter+tcpFilter+ssFilter+iptFilter+throughputFilter+bufferFilter+topFilter
	showFilter = dropFilter+errorFilter+bufferFilter  +throughputFilter+topFilter+ssFilter+iptFilter
	#print command["pack"]["result"]
	result = [i for i in showFilter if i in command["pack"]["result"]]
	otherFilter = [i for i in command["pack"]["result"] if i not in allFilter]

	#filterout CPU-percentage
	#otherFilter = [i for i in otherFilter if not i.startswith("cpu") and not i.startswith("ESTAB") and not i.startswith("dev") and not i.startswith("Ip")]

	if global_conf["other"]:
		result += otherFilter
	command["rate"]["showFilter"] = result
	
	#rate/show result
	goThrough(filename, "rate", evaluate=True)
	command["rate"]["first"] = True
	command["rate"]["result"] =[]
	goThrough(filename, "rate")
	
if __name__ == '__main__':
	try:
		options, args = getopt.getopt(sys.argv[1:], "o:f:p:i:r", ["other", "file", "port", "interface", "raw"])
	except getopt.GetoptError:
		print "arguments parse error!"
		sys.exit()
	
	for k,v in options:
		if k in ("-o","--other"):
			global_conf["other"] = True
		if k in ("-f","--file"):
			global_conf["logfile"] = v
		if k in ("-p","--port"):
			global_conf["port"] = long(v)
		if k in ("-i","--interface"):
			global_conf["intf"] = v
		if k in ("-r","--raw"):
			global_conf["raw"] = True
	
	main(args[0])

