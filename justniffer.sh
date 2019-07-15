# wireshark-like command-line tool
justniffer -a -n N/A '%source.ip:%source.port %tab| %connection.time %tab| %request.time %tab| %response.time.begin %tab| %response.time.end' -f $1
