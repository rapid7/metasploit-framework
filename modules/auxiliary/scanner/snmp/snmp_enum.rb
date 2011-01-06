##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'snmp'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::SNMPClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner


	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'SNMP Enumeration Module',
			'Version'     => '$Revision$',
			'Description' => 'This module allows enumeration of any devices with SNMP
				protocol support. It supports hardware, software, and network.
				The default community used is "public".',
			'References'  =>
				[
					[ 'URL', 'http://en.wikipedia.org/wiki/Simple_Network_Management_Protocol' ],
					[ 'URL', 'http://net-snmp.sourceforge.net/docs/man/snmpwalk.html' ],
					[ 'URL', 'http://www.nothink.org/perl/snmpcheck/' ],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		))
	end

	def run_host(ip)

		begin
			snmp = connect_snmp

			#
			#
			#
		
			sysName = snmp.get_value('1.3.6.1.2.1.1.5.0').to_s
			if (sysName.to_s.empty? or sysName.to_s =~ /Null/)
				sysName = '-'
			end
			
			sysDesc = snmp.get_value('1.3.6.1.2.1.1.1.0').to_s
			if (sysDesc.to_s.empty? or sysDesc.to_s =~ /Null/)
				sysDesc = '-'
			end
			sysDesc.gsub!(/^\s+|\s+$|\n+|\r+/, ' ')
			
			sysContact = snmp.get_value('1.3.6.1.2.1.1.4.0').to_s
			if (sysContact.to_s.empty? or sysContact.to_s =~ /Null/)
				sysContact = '-'
			end
			
			sysLocation = snmp.get_value('1.3.6.1.2.1.1.6.0').to_s
			if (sysLocation.to_s.empty? or sysLocation.to_s =~ /Null/)
				sysLocation = '-'
			end
			
			sysUpTimeInstance = snmp.get_value('1.3.6.1.2.1.1.3.0')
			
			hrSystemUptime = snmp.get_value('1.3.6.1.2.1.25.1.1.0')
			hrSystemUptime = '-' if hrSystemUptime.to_s =~ /Null/
			
			systemDate = snmp.get_value('1.3.6.1.2.1.25.1.2.0')
			if (systemDate.to_s.empty? or systemDate.to_s =~ /Null/)
				systemDate = '-'
			else
				dtm = systemDate.unpack("NCCCCCC")
				systemDate = "#{dtm[0]}-#{dtm[1]}-#{dtm[2]} #{dtm[3]}:#{dtm[4]}:#{dtm[5]}"
			end

			#
			#
			#

			print_status("System information")
			print_line("")


			sysName = sysName.strip
			sysDesc = sysDesc.strip
			sysContact = sysContact.strip
			sysLocation = sysLocation.strip

			print_line("Hostname                : #{sysName}")
			print_line("Description             : #{sysDesc}")
			print_line("Contact                 : #{sysContact}")
			print_line("Location                : #{sysLocation}")
			print_line("Uptime snmp             : #{sysUpTimeInstance}")
			print_line("Uptime system           : #{hrSystemUptime}")
			print_line("System date             : #{systemDate}")
		
			
			if sysName.length > 0
				report_note(
					:host  => ip,
					:proto => 'snmp',
					:port  => datastore['RPORT'].to_i,
					:type  => 'snmp.sysName',
				:data  => sysName.strip
				)
			end
			
			if sysDesc.length > 0
				report_note(
					:host  => ip,
					:proto => 'snmp',
					:port  => datastore['RPORT'].to_i,
					:type  => 'snmp.sysDesc',
					:data  => sysDesc.strip
				)
			end
			
			if (sysDesc =~ /Windows/)
				
				domPrimaryDomain = snmp.get_value('1.3.6.1.4.1.77.1.4.1')
				domPrimaryDomain = '-' if domPrimaryDomain.to_s =~ /Null/
				print_line("Domain                  : #{domPrimaryDomain}")
			
				#
				#
				#
		
				users = []

				snmp.walk(["1.3.6.1.4.1.77.1.2.25.1.1","1.3.6.1.4.1.77.1.2.25.1"]) do |user,entry|
					users.push([[user.value]])
				end
			
				if not users.empty?
					print_line('')
					print_status("User accounts\n")
					users.each {|a| print_line("#{a}")}
				end
			end
			
			#
			#
			#

			network_information = []

			ipForwarding = snmp.get_value('1.3.6.1.2.1.4.1.0')
			
			if ipForwarding == 0 || ipForwarding == 2 
				ipForwarding = "no"
				network_information.push([["IP forwarding enabled   : "],[ipForwarding]])
			elsif ipForwarding == 1
				ipForwarding = "yes"
				network_information.push([["IP forwarding enabled   : "],[ipForwarding]])
			end
			
			ipDefaultTTL = snmp.get_value('1.3.6.1.2.1.4.2.0')
			if ipDefaultTTL.to_s !~ /Null/
				network_information.push([["Default TTL             : "],[ipDefaultTTL]])
			end
			
			tcpInSegs = snmp.get_value('1.3.6.1.2.1.6.10.0')
			if tcpInSegs.to_s !~ /Null/
				network_information.push([["TCP segments received   : "],[tcpInSegs]])
			end
			
			tcpOutSegs = snmp.get_value('1.3.6.1.2.1.6.11.0')
			if tcpOutSegs.to_s !~ /Null/
				network_information.push([["TCP segments sent       : "],[tcpOutSegs]])
			end
			
			tcpRetransSegs = snmp.get_value('1.3.6.1.2.1.6.11.0')
			if tcpRetransSegs.to_s !~ /Null/
				network_information.push([["TCP segments retrans.   : "],[tcpRetransSegs]])
			end
			
			ipInReceives = snmp.get_value('1.3.6.1.2.1.4.3.0')
			if ipInReceives.to_s !~ /Null/
				network_information.push([["Input datagrams         : "],[ipInReceives]])
			end
			
			ipInDelivers = snmp.get_value('1.3.6.1.2.1.4.9.0')
			if ipInDelivers.to_s !~ /Null/
				network_information.push([["Delivered datagrams     : "],[ipInDelivers]])
			end
			
			ipOutRequests = snmp.get_value('1.3.6.1.2.1.4.10.0')
			if ipOutRequests.to_s !~ /Null/
				network_information.push([["Output datagrams        : "],[ipOutRequests]])
			end
			
			if not network_information.empty?
				print_line('')
				print_status("Network information")
				print_line('')
				network_information.each {|a,b| print_line("#{a} #{b}")}
			end
			
			#
			#
			#

			network_interfaces = []

			snmp.walk(["1.3.6.1.2.1.2.2.1.1","1.3.6.1.2.1.2.2.1.2","1.3.6.1.2.1.2.2.1.6","1.3.6.1.2.1.2.2.1.3","1.3.6.1.2.1.2.2.1.4","1.3.6.1.2.1.2.2.1.5","1.3.6.1.2.1.2.2.1.10","1.3.6.1.2.1.2.2.1.16","1.3.6.1.2.1.2.2.1.7"]) do |index,descr,mac,type,mtu,speed,inoc,outoc,status|
					
				ifindex  = index.value
				ifdescr  = descr.value
				ifmac    = mac.value.unpack("H2H2H2H2H2H2").join(":")
				iftype   = type.value
				ifmtu    = mtu.value
				ifspeed  = speed.value.to_i
				ifinoc   = inoc.value
				ifoutoc  = outoc.value
				ifstatus = status.value
				
				case iftype
				when 1
					iftype = "other"
				when 2 
					iftype = "regular1822"
				when 3
					iftype = "hdh1822"
				when 4
					iftype = "ddn-x25"
				when 5
					iftype = "rfc877-x25"
				when 6
					iftype = "ethernet-csmacd"
				when 7
					iftype = "iso88023-csmacd"
				when 8
					iftype = "iso88024-tokenBus"
				when 9
					iftype = "iso88025-tokenRing"
				when 10
					iftype = "iso88026-man"
				when 11
					iftype = "starLan"
				when 12
					iftype = "proteon-10Mbit"
				when 13
					iftype = "proteon-80Mbit"
				when 14
					iftype = "hyperchannel"
				when 15
					iftype = "fddi"
				when 16
					iftype = "lapb"
				when 17
					iftype = "sdlc"
				when 18
					iftype = "ds1"
				when 19
					iftype = "e1"
				when 20
					iftype = "basicISDN"
				when 21
					iftype = "primaryISDN"
				when 22
					iftype = "propPointToPointSerial"
				when 23
					iftype = "ppp"
				when 24
					iftype = "softwareLoopback"
				when 25
					iftype = "eon"
				when 26
					iftype = "ethernet-3Mbit"
				when 27
					iftype = "nsip"
				when 28
					iftype = "slip"
				when 29
					iftype = "ultra"
				when 30
					iftype = "ds3"
				when 31
					iftype = "sip"
				when 32
					iftype = "frame-relay"
				else
					iftype = "unknown"
				end

				case ifstatus
				when 1
					ifstatus = "up"
				when 2
					ifstatus = "down"
				when 3
					ifstatus = "testing"
				else
					ifstatus = "unknown"
				end

				ifspeed = ifspeed / 1000000

				network_interfaces.push([[ifstatus],[ifdescr],[ifindex],[ifmac],[iftype],[ifspeed],[ifmtu],[ifinoc],[ifoutoc]])
			end
			
			if not network_interfaces.empty?
				print_line('')
				print_status("Network interfaces")
				print_line('')
				network_interfaces.each {|a,b,c,d,e,f,g,h,i|
					print_line("Interface [ #{a} ] #{b}")
					print_line('')
					print_line("\tId              : #{c}")
					print_line("\tMac address     : #{d}")
					print_line("\tType            : #{e}")
					print_line("\tSpeed           : #{f} Mbps")
					print_line("\tMtu             : #{g}")
					print_line("\tIn octets       : #{h}")
					print_line("\tOut octets      : #{i}")
					print_line('')
				}
			end
			
			#
			#
			#

			network_ip = []

			snmp.walk(["1.3.6.1.2.1.4.20.1.2","1.3.6.1.2.1.4.20.1.1","1.3.6.1.2.1.4.20.1.3","1.3.6.1.2.1.4.20.1.4"]) do |ifid,ipaddr,netmask,bcast|
				network_ip.push([[ifid.value],[ipaddr.value],[netmask.value],[bcast.value]])
			end
			
			if not network_ip.empty?
				print_line('')
				print_status("Network IP")
				print_line('')
				print_line(sprintf("%16s %16s %16s %16s","Id","IP Address","Netmask","Broadcast"))
				print_line('')
				network_ip.each {|a,b,c,d| print_line(sprintf("%16s %16s %16s %16s",a,b,c,d))}
			end
			
			#
			#
			#

			routing = []

			snmp.walk(["1.3.6.1.2.1.4.21.1.1","1.3.6.1.2.1.4.21.1.7","1.3.6.1.2.1.4.21.1.11","1.3.6.1.2.1.4.21.1.3"]) do |dest,hop,mask,metric|
				if (metric.value.to_s.empty?)
					metric.value = '-'
				end
				routing.push([[dest.value],[hop.value],[mask.value],[metric.value]])
			end
			
			if not routing.empty?
				print_line('')
				print_status("Routing information")
				print_line('')
				print_line(sprintf("%16s %16s %16s %16s","Destination","Next hop","Mask","Metric"))
				print_line('')
				routing.each {|a,b,c,d| print_line(sprintf("%16s %16s %16s %16s",a,b,c,d))}
			end
			
			#
			#
			#

			tcp = []

			snmp.walk(["1.3.6.1.2.1.6.13.1.2","1.3.6.1.2.1.6.13.1.3","1.3.6.1.2.1.6.13.1.4","1.3.6.1.2.1.6.13.1.5","1.3.6.1.2.1.6.13.1.1"]) do |ladd,lport,radd,rport,state|
				
				if (ladd.value.to_s.empty?  or ladd.value.to_s =~ /noSuchInstance/)
					ladd = "-"
				else
					ladd  = ladd.value
				end

				if (lport.value.to_s.empty? or lport.value.to_s =~ /noSuchInstance/)
					lport = "-"
				else
					lport = lport.value
				end

				if (radd.value.to_s.empty?  or radd.value.to_s =~ /noSuchInstance/)
					radd = "-"
				else
					radd  = radd.value
				end

				if (rport.value.to_s.empty? or rport.value.to_s =~ /noSuchInstance/)
					rport = "-"
				else
					rport = rport.value
				end
			
				case state.value
				when 1
					state = "closed"
				when 2
					state = "listen"
				when 3
					state = "synSent"
				when 4
					state = "synReceived"
				when 5
					state = "established"
				when 6
					state = "finWait1"
				when 7
					state = "finWait2"
				when 8
					state = "closeWait"
				when 9
					state = "lastAck"
				when 10
					state = "closing"
				when 11
					state = "timeWait"
				when 12
					state = "deleteTCB"
				else
					state = "unknown"
				end

				tcp.push([[ladd],[lport],[radd],[rport],[state]])
			end
			
			if not tcp.empty?
				print_line('')
				print_status("TCP connections and listening ports")
				print_line('')
				print_line(sprintf("%16s %16s %16s %16s %16s","Local address","Local port","Remote address","Remote port","State"))
				print_line('')
				tcp.each {|a,b,c,d,e| print_line(sprintf("%16s %16s %16s %16s %16s",a,b,c,d,e))}
			end
			
			#
			#
			#

			udp = []

			snmp.walk(["1.3.6.1.2.1.7.5.1.1","1.3.6.1.2.1.7.5.1.2"]) do |ladd,lport|
				udp.push([[ladd.value],[lport.value]])
			end
		
			if not udp.empty? 
				print_line('')
				print_status("Listening UDP ports")
				print_line('')
				print_line(sprintf("%16s %16s","Local address","Local port"))
				print_line('')
				udp.each {|a,b| print_line(sprintf("%16s %16s",a,b))}
			end
			
			#
			#
			#
			
			if (sysDesc =~ /Windows/)
				
				#
				#
				#

				network_services = []

				n = 0
				
				snmp.walk(["1.3.6.1.4.1.77.1.2.3.1.1","1.3.6.1.4.1.77.1.2.3.1.2"]) do |name,installed|
					network_services.push([[n],[name.value]])
					n+=1
				end
			
				if not network_services.empty? 
					print_line('')
					print_status("Network services")
					print_line('')
					print_line(sprintf("%10s %s","Index","Name"))
					print_line('')
					network_services.each {|a,b| print_line(sprintf("%10s %s",a,b))}
				end
			
				#
				#
				#
		
				share = []

				snmp.walk(["1.3.6.1.4.1.77.1.2.27.1.1","1.3.6.1.4.1.77.1.2.27.1.2","1.3.6.1.4.1.77.1.2.27.1.3"]) do |name,path,comment|
					share.push([[name.value],[path.value],[comment.value]])
				end
				
				if not share.empty? 
					print_line('')
					print_status("Share")
					print_line('')
					share.each {|a,b,c|
						print_line("Name                      : #{a}") 
						print_line("Path                      : #{b}")
						print_line("Comment                   : #{c}")
						print_line('')
					}
				end
				
				#
				#
				#

				iis = []

				http_totalBytesSentLowWord = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.2.0')
				if http_totalBytesSentLowWord.to_s !~ /Null/
					iis.push([["TotalBytesSentLowWord     : "],[http_totalBytesSentLowWord]])
				end
				
				http_totalBytesReceivedLowWord = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.4.0')
				if http_totalBytesReceivedLowWord.to_s !~ /Null/
					iis.push([["TotalBytesReceivedLowWord : "],[http_totalBytesReceivedLowWord]])
				end
				
				http_totalFilesSent = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.5.0')
				if http_totalFilesSent.to_s !~ /Null/
					iis.push([["TotalFilesSent            : "],[http_totalFilesSent]])
				end
				
				http_currentAnonymousUsers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.6.0')
				if http_currentAnonymousUsers.to_s !~ /Null/
					iis.push([["CurrentAnonymousUsers     : "],[http_currentAnonymousUsers]])
				end

				http_currentNonAnonymousUsers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.7.0')
				if http_currentNonAnonymousUsers.to_s !~ /Null/
					iis.push([["CurrentNonAnonymousUsers  : "],[http_currentNonAnonymousUsers]])
				end

				http_totalAnonymousUsers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.8.0')
				if http_totalAnonymousUsers.to_s !~ /Null/
					iis.push([["TotalAnonymousUsers       : "],[http_totalAnonymousUsers]])
				end

				http_totalNonAnonymousUsers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.9.0')
				if http_totalNonAnonymousUsers.to_s !~ /Null/
					iis.push([["TotalNonAnonymousUsers    : "],[http_totalNonAnonymousUsers]])
				end

				http_maxAnonymousUsers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.10.0')
				if http_maxAnonymousUsers.to_s !~ /Null/
					iis.push([["MaxAnonymousUsers         : "],[http_maxAnonymousUsers]])
				end

				http_maxNonAnonymousUsers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.11.0')
				if http_maxNonAnonymousUsers.to_s !~ /Null/
					iis.push([["MaxNonAnonymousUsers      : "],[http_maxNonAnonymousUsers]])
				end

				http_currentConnections = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.12.0')
				if http_currentConnections.to_s !~ /Null/
					iis.push([["CurrentConnections        : "],[http_currentConnections]])
				end

				http_maxConnections = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.13.0')
				if http_maxConnections.to_s !~ /Null/
					iis.push([["MaxConnections            : "],[http_maxConnections]])
				end
				
				http_connectionAttempts = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.14.0')
				if http_connectionAttempts.to_s !~ /Null/
					iis.push([["ConnectionAttempts        : "],[http_connectionAttempts]])
				end

				http_logonAttempts = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.15.0')
				if http_logonAttempts.to_s !~ /Null/
					iis.push([["LogonAttempts             : "],[http_logonAttempts]])
				end

				http_totalGets = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.16.0')
				if http_totalGets.to_s !~ /Null/
					iis.push([["Gets                      : "],[http_totalGets]])
				end

				http_totalPosts = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.17.0')
				if http_totalPosts.to_s !~ /Null/
					iis.push([["Posts                     : "],[http_totalPosts]])
				end

				http_totalHeads = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.18.0')
				if http_totalHeads.to_s !~ /Null/
					iis.push([["Heads                     : "],[http_totalHeads]])
				end

				http_totalOthers = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.19.0')
				if http_totalOthers.to_s !~ /Null/
					iis.push([["Others                    : "],[http_totalOthers]])
				end
				
				http_totalCGIRequests = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.20.0')
				if http_totalCGIRequests.to_s !~ /Null/
					iis.push([["CGIRequests               : "],[http_totalCGIRequests]])
				end
				
				http_totalBGIRequests = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.21.0')
				if http_totalBGIRequests.to_s !~ /Null/
					iis.push([["BGIRequests               : "],[http_totalBGIRequests]])
				end
				
				http_totalNotFoundErrors = snmp.get_value('1.3.6.1.4.1.311.1.7.3.1.22.0')
				if http_totalNotFoundErrors.to_s !~ /Null/
					iis.push([["NotFoundErrors            : "],[http_totalNotFoundErrors]])
				end
				
				if not iis.empty? 
					print_line('')
					print_status("IIS server information")
					print_line('')
					iis.each {|a,b| print_line("#{a} #{b}")}
				end
			end
			
			#
			#
			#
			
			storage_information = []

			snmp.walk(["1.3.6.1.2.1.25.2.3.1.1","1.3.6.1.2.1.25.2.3.1.2","1.3.6.1.2.1.25.2.3.1.3","1.3.6.1.2.1.25.2.3.1.4","1.3.6.1.2.1.25.2.3.1.5","1.3.6.1.2.1.25.2.3.1.6"]) do |index,type,descr,allocation,size,used|

				case type.value.to_s
				when /^1.3.6.1.2.1.25.2.1.1$/
					type.value = "Other"
				when /^1.3.6.1.2.1.25.2.1.2$/
					type.value = "Ram"
				when /^1.3.6.1.2.1.25.2.1.3$/
					type.value = "Virtual Memory"
				when /^1.3.6.1.2.1.25.2.1.4$/
					type.value = "Fixed Disk"
				when /^1.3.6.1.2.1.25.2.1.5$/
					type.value = "Removable Disk"
				when /^1.3.6.1.2.1.25.2.1.6$/
					type.value = "Floppy Disk"
				when /^1.3.6.1.2.1.25.2.1.7$/
					type.value = "Compact Disc"
				when /^1.3.6.1.2.1.25.2.1.8$/
					type.value = "RamDisk"
				when /^1.3.6.1.2.1.25.2.1.9$/
					type.value = "Flash Memory"
				when /^1.3.6.1.2.1.25.2.1.10$/
					type.value = "Network Disk"
				else
					type.value = "unknown"
				end

				allocation.value = "unknown" if allocation.value.to_s =~ /noSuchInstance/
				size.value = "unknown" if size.value.to_s =~ /noSuchInstance/
				used.value = "unknown" if used.value.to_s =~ /noSuchInstance/

				storage_information.push([[descr.value],[index.value],[type.value],[allocation.value],[size.value],[used.value]])
			end
			
			if not storage_information.empty? 
				print_line('')
				print_status("Storage information")
				print_line('')
				storage_information.each {|a,b,c,d,e,f|
					
					e = number_to_human_size(e,d)
					f = number_to_human_size(f,d)
					
					print_line("#{a}")
					print_line("\tDevice id         : #{b}")
					print_line("\tFilesystem type   : #{c}")
					print_line("\tDevice unit       : #{d}")
					print_line("\tMemory size       : #{e}")
					print_line("\tMemory used       : #{f}")
					print_line('')
				}
			end
			
			#
			#
			#
		
			file_system = []

			hrFSIndex = snmp.get_value('1.3.6.1.2.1.25.3.8.1.1.1')
			if hrFSIndex.to_s !~ /Null/
				file_system.push([["Index                     : "],[hrFSIndex]])
			end
			
			hrFSMountPoint = snmp.get_value('1.3.6.1.2.1.25.3.8.1.2.1')
			if hrFSMountPoint.to_s !~ /Null/
				file_system.push([["Mount point               : "],[hrFSMountPoint]])
			end
			
			hrFSRemoteMountPoint = snmp.get_value('1.3.6.1.2.1.25.3.8.1.3.1')
			if hrFSRemoteMountPoint.to_s !~ /Null/
				file_system.push([["Remote mount point        : "],[hrFSRemoteMountPoint]])
			end
			
			hrFSType = snmp.get_value('1.3.6.1.2.1.25.3.8.1.4.1')

			case hrFSType.to_s
			when /^1.3.6.1.2.1.25.3.9.1$/
				hrFSType = "Other"
			when /^1.3.6.1.2.1.25.3.9.2$/
				hrFSType = "Unknown"
			when /^1.3.6.1.2.1.25.3.9.3$/
				hrFSType = "BerkeleyFFS"
			when /^1.3.6.1.2.1.25.3.9.4$/
				hrFSType = "Sys5FS"
			when /^1.3.6.1.2.1.25.3.9.5$/
				hrFSType = "Fat"
			when /^1.3.6.1.2.1.25.3.9.6$/
				hrFSType = "HPFS"
			when /^1.3.6.1.2.1.25.3.9.7$/
				hrFSType = "HFS"
			when /^1.3.6.1.2.1.25.3.9.8$/
				hrFSType = "MFS"
			when /^1.3.6.1.2.1.25.3.9.9$/
				hrFSType = "NTFS"
			when /^1.3.6.1.2.1.25.3.9.10$/
				hrFSType = "VNode"
			when /^1.3.6.1.2.1.25.3.9.11$/
				hrFSType = "Journaled"
			when /^1.3.6.1.2.1.25.3.9.12$/
				hrFSType = "iso9660"
			when /^1.3.6.1.2.1.25.3.9.13$/
				hrFSType = "RockRidge"
			when /^1.3.6.1.2.1.25.3.9.14$/
				hrFSType = "NFS"
			when /^1.3.6.1.2.1.25.3.9.15$/
				hrFSType = "Netware"
			when /^1.3.6.1.2.1.25.3.9.16$/
				hrFSType = "AFS"
			when /^1.3.6.1.2.1.25.3.9.17$/
				hrFSType = "DFS"
			when /^1.3.6.1.2.1.25.3.9.18$/
				hrFSType = "Appleshare"
			when /^1.3.6.1.2.1.25.3.9.19$/
				hrFSType = "RFS"
			when /^1.3.6.1.2.1.25.3.9.20$/
				hrFSType = "DGCFS"
			when /^1.3.6.1.2.1.25.3.9.21$/
				hrFSType = "BFS"
			when /^1.3.6.1.2.1.25.3.9.22$/
				hrFSType = "FAT32"
			when /^1.3.6.1.2.1.25.3.9.23$/
				hrFSType = "LinuxExt2"
			else
				hrFSType = "Null"
			end
			
			if hrFSType.to_s !~ /Null/
				file_system.push([["Type                      : "],[hrFSType]])
			end

			hrFSAccess = snmp.get_value('1.3.6.1.2.1.25.3.8.1.5.1')
			if hrFSAccess.to_s !~ /Null/
				file_system.push([["Access                    : "],[hrFSAccess]])
			end
			
			hrFSBootable = snmp.get_value('1.3.6.1.2.1.25.3.8.1.6.1')
			if hrFSBootable.to_s !~ /Null/
				file_system.push([["Bootable                  : "],[hrFSBootable]])
			end
			
			if not file_system.empty?
				print_line('')
				print_status("File system information")
				print_line('')
				file_system.each {|a,b| print_line("#{a} #{b}")}
			end

			#
			#
			#

			device_information = []

			snmp.walk(["1.3.6.1.2.1.25.3.2.1.1","1.3.6.1.2.1.25.3.2.1.2","1.3.6.1.2.1.25.3.2.1.5","1.3.6.1.2.1.25.3.2.1.3"]) do |index,type,status,descr|
				
				case type.value
				when /^1.3.6.1.2.1.25.3.1.1$/
					type.value = "Other"
				when /^1.3.6.1.2.1.25.3.1.2$/
					type.value = "Unknown"
				when /^1.3.6.1.2.1.25.3.1.3$/
					type.value = "Processor"
				when /^1.3.6.1.2.1.25.3.1.4$/
					type.value = "Network"
				when /^1.3.6.1.2.1.25.3.1.5$/
					type.value = "Printer"
				when /^1.3.6.1.2.1.25.3.1.6$/
					type.value = "Disk Storage"
				when /^1.3.6.1.2.1.25.3.1.10$/
					type.value = "Video"
				when /^1.3.6.1.2.1.25.3.1.11$/
					type.value = "Audio"
				when /^1.3.6.1.2.1.25.3.1.12$/
					type.value = "Coprocessor"
				when /^1.3.6.1.2.1.25.3.1.13$/
					type.value = "Keyboard"
				when /^1.3.6.1.2.1.25.3.1.14$/
					type.value = "Modem"
				when /^1.3.6.1.2.1.25.3.1.15$/
					type.value = "Parallel Port"
				when /^1.3.6.1.2.1.25.3.1.16$/
					type.value = "Pointing"
				when /^1.3.6.1.2.1.25.3.1.17$/
					type.value = "Serial Port"
				when /^1.3.6.1.2.1.25.3.1.18$/
					type.value = "Tape"
				when /^1.3.6.1.2.1.25.3.1.19$/
					type.value = "Clock"
				when /^1.3.6.1.2.1.25.3.1.20$/
					type.value = "Volatile Memory"
				when /^1.3.6.1.2.1.25.3.1.21$/
					type.value = "Non Volatile Memory"
				else
					type.value = "unknown"
				end
	
				case status.value
				when 1
					status.value = "unknown"
				when 2
					status.value = "running"
				when 3
					status.value = "warning"
				when 4
					status.value = "testing"
				when 5
					status.value = "down"
				else
					status.value = "unknown"
				end

				descr.value = "unknown" if descr.value.to_s =~ /noSuchInstance/

				device_information.push([[index.value],[type.value],[status.value],[descr.value]])
			end
			
			if not device_information.empty? 
				print_line('')
				print_status("Device information")
				print_line('')
				print_line(sprintf("%10s %22s %15s %s","Id","Type","Status","Descr"))
				print_line('')
				device_information.each {|a,b,c,d| print_line(sprintf("%10s %22s %15s %s",a,b,c,d))}
			end

			#
			#
			#

			software_list = []

			snmp.walk(["1.3.6.1.2.1.25.6.3.1.1","1.3.6.1.2.1.25.6.3.1.2"]) do |index,name|
				software_list.push([[index.value],[name.value]])
			end

			if not software_list.empty? 
				print_line('')
				print_status("Software components")
				print_line('')
				print_line(sprintf("%10s %s","Index","Name"))
				print_line('')
				software_list.each {|a,b| print_line(sprintf("%10s %s",a,b))}
			end

			#
			#
			#

			process_interfaces = []

			snmp.walk(["1.3.6.1.2.1.25.4.2.1.1","1.3.6.1.2.1.25.4.2.1.2","1.3.6.1.2.1.25.4.2.1.4","1.3.6.1.2.1.25.4.2.1.5","1.3.6.1.2.1.25.4.2.1.7"]) do |id,name,path,param,status|

				if status.value == 1
					status.value = "running"
				elsif status.value == 2
					status.value = "runnable"
				else
					status.value = "unknown"
				end
				
				process_interfaces.push([[id.value],[status.value],[name.value],[path.value],[param.value]])
			end
			
			if not process_interfaces.empty? 
				print_line('')
				print_status("Process interfaces")
				print_line('')
				print_line(sprintf("%10s %10s %22s %30s %s","Id","Status","Name","Path","Parameters"))
				print_line('')
				process_interfaces.each {|a,b,c,d,e| print_line(sprintf("%10s %10s %22s %30s %s",a,b,c,d,e))}
			end
			
			#
			#
			#

			print_line('')

			disconnect_snmp

		rescue SNMP::RequestTimeout
			print_status("#{ip}, SNMP request timeout.")
		rescue Errno::ECONNREFUSED
			print_status("#{ip}, Connection refused.")
		rescue SNMP::InvalidIpAddress
			print_status("#{ip}, Invalid Ip Address. Check it with 'snmpwalk tool'.")
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_status("Unknown error: #{e.class} #{e}")
		end
	end

	def number_to_human_size(size,unit)
		size = size.first.to_i * unit.first.to_i 

		if size < 1024
			"#{size} bytes"
		elsif size < 1024.0 * 1024.0
			"%.02f KB" % (size / 1024.0)
		elsif size < 1024.0 * 1024.0 * 1024.0
			"%.02f MB" % (size / 1024.0 / 1024.0)
		else
			"%.02f GB" % (size / 1024.0 / 1024.0 / 1024.0)
		end
	end
end
