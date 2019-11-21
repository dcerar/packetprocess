# packetprocess
This program reads packets from the network and generate statistics for TCP, UDP and ICMP protocols according to the following table (open this file in raw mode to see it):

Protocol                        Fields (CSV file)	                             Log file
TCP	          year,month,day,hour,minute,second,source IP, source port	      tcplog.csv
UDP           year,month,day,hour,minute,second,source IP, source port	      udplog.csv
ICMP	        year,month,day,hour,minute,second,source IP, ICMP Type number	  icmplog.csv

Compile with command:
gcc packetprocess.c -o packetprocess -lpcap

If you get an error "fatal error: pcap.h: No such file or directory", you need to install libpcap-dev.
