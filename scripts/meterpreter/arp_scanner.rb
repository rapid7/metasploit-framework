# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
@client = client
@@exec_opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-i" => [ false, "Enumerate Local Interfaces"],
	"-r" => [ true,  "The target address range or CIDR identifier"],
	"-s" => [ false,  "Save found IP Addresses to logs."]
)



def enum_int
	print_status("Enumerating Interfaces")
	client.net.config.interfaces.each do |i|
		if not i.mac_name =~ /Loopback/
			print_status("\t#{i.mac_name}")
			print_status("\t#{i.ip}")
			print_status("\t#{i.netmask}")
			print_status()
		end

	end
end

def arp_scan(cidr)
	print_status("ARP Scanning #{cidr}")
	ws = client.railgun.ws2_32
	iphlp = client.railgun.iphlpapi
	i, a = 0, []
	iplst,found = [],""
	ipadd = Rex::Socket::RangeWalker.new(cidr)
	numip = ipadd.num_ips
	while (iplst.length < numip)
		ipa = ipadd.next_ip
		if (not ipa)
			break
		end
		iplst << ipa
	end
	iplst.each do |ip_text|
		if i < 10
			a.push(::Thread.new {
					h = ws.inet_addr(ip_text)
					ip = h["return"]
					h = iphlp.SendARP(ip,0,6,6)
					if h["return"] == client.railgun.const("NO_ERROR")
						mac_text = h["pMacAddr"].unpack('C*').map { |e| "%02x" % e }.join(':')
						print_status("IP: #{ip_text} MAC #{mac_text}")
						found << "#{ip_text}\n"
					end
				})
			i += 1
		else
			sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
			i = 0
		end
	end
	a.delete_if {|x| not x.alive?} while not a.empty?
	return found
end

def save_found(found_ip)
	info = @client.sys.config.sysinfo
	# Create Filename info to be appended to downloaded files
	filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

	# Create a directory for the logs
	logs = ::File.join(Msf::Config.log_directory,'scripts', 'arp_scanner',Rex::FileUtils.clean_path(info['Computer'] + filenameinfo))
	# Create the log directory
	::FileUtils.mkdir_p(logs)

	#log file name
	dest = Rex::FileUtils.clean_path(logs + "/" + info['Computer'] + filenameinfo + ".txt")

	print_status("Saving found IP's to #{dest}")
	file_local_write(dest,found_ip)

end
save2log = false
cidr2scan = ""
@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line "Meterpreter Script for performing an ARPS Scan Discovery."
		print_line(@@exec_opts.usage)
		raise Rex::Script::Completed
	when "-i"
		enum_int
		raise Rex::Script::Completed
	when "-r"
		cidr2scan = val
	when "-s"
		save2log = true
	end
}
if client.platform =~ /win32|win64/
	if args.length > 0
		if save2log
			save_found(arp_scan(cidr2scan))
		else
			arp_scan(cidr2scan)
		end
	else
		print_line "Meterpreter Script for performing an ARPS Scan Discovery."
		print_line(@@exec_opts.usage)
		raise Rex::Script::Completed
	end
else
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
