# packetprocess
This program reads packets from the network and generate statistics for TCP, UDP and ICMP protocols according to the following table:

Protocol                        Fields (CSV file)	                             Log file
TCP	          year,month,day,hour,minute,second,source IP, source port	      tcplog.csv
UDP           year,month,day,hour,minute,second,source IP, source port	      udplog.csv
ICMP	        year,month,day,hour,minute,second,source IP, ICMP Type number	  icmplog.csv
