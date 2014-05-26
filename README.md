
This is old, it's from 2010, I vaguely recall that it does stuff. Lets see what Jules the younger had to say

julian@jbg.za.org

############################################################################################################



- kknd 0.3 alpha 20.01.2010
  JB Gericke
  julian@sasquatchpie.co.za

Rapidly and persistently blacklist/drop or reject suspicious traffic and it's corresponding source. 

Requirements:

Syslog-ng, iptables, ulogd and the following perl modules:

	- IPTables::libiptc
	- Config::Simple
	- Daemon::Generic

Setup:

[*] Create the pipe from which kknd will read:

	mkfifo /var/log/iptables.pipe

[*] Install ulogd and configure it to record entries to a separate file (ulogd.conf):

	[LOGEMU]
	file="/var/log/ulog/iptables.log"
	sync=1

[*] Add the ulog log file as a source within syslog-ng, setting it's destination to the pipe created earlier (syslog-ng.conf). Tune the follow frequency as needed, 10 should be fine though:

        source s_iptables {
        file("/var/log/ulog/iptables.log" follow-freq(10) log_fetch_limit(1) flags(no-parse) log_prefix("iptables: "));
        };
        destination iptableslog { pipe("/var/log/iptables.pipe"); };
        log { source(s_iptables); destination(iptableslog); };

[*] Create a new chain that will handle logging of flags you deem suspicious, eg LOGDROPC:

	iptables -N LOGDROPC
	iptables -F LOGDROPC

[*] Use ulog to pump output away from system log files. Note kknd will only work with the below format, although you can change whatever you want between the square braces within the prefix:

	iptables -A LOGDROPC -p tcp --tcp-flags SYN,FIN SYN,FIN -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ SYN/FIN/SYN/FIN ]"
	iptables -A LOGDROPC -p tcp --tcp-flags SYN,RST SYN,RST -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ SYN/RST/SYN/RST ]"
	iptables -A LOGDROPC -p tcp --tcp-flags FIN,RST FIN,RST -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ FIN/RST/FIN/RST ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ACK,FIN FIN -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ ACK/FIN/FIN ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ACK,PSH PSH -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ ACK/PSH/PSH ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ACK,URG URG -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ ACK/URG/URG ]"
	iptables -A LOGDROPC -p tcp --tcp-flags SYN,RST,ACK SYN -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ SYN/RST/ACK/SYN ]"	
	iptables -A LOGDROPC -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ F/S/R/P/A/U/N ]"
	iptables -A LOGDROPC -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ FIN/SYN/FIN/SYN ]"
	iptables -A LOGDROPC -p tcp -m tcp --tcp-flags FIN,ACK FIN -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ FIN/ACK/FIN ]"
	iptables -A LOGDROPC -p tcp -m tcp --tcp-flags PSH,ACK PSH -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ PSH/ACK/PSH ]"
	iptables -A LOGDROPC -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ S/A/F/R/R ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ALL FIN,URG,PSH -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ ALL FIN/URG/PSH ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ALL ALL -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ ALL,ALL ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ SYN/RST/ACK/FIN/URG ]"
	iptables -A LOGDROPC -p tcp --tcp-flags ALL NONE -m limit --limit 5/minute -j ULOG --ulog-nlgroup 1 --ulog-cprange 100 --ulog-prefix "iptables [ NULL ]"
	iptables -A INPUT -j LOGDROPC

[*] Create /usr/local/etc/kknd directory and move kknd.conf there, along with the whitelist & shitlist. Move kknd to /usr/local/sbin/ and execute.

TODO: Finish port blink 
      Get off Ulog
      precreate tables

       

