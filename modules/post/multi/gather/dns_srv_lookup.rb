##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'


class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Auxiliary::Report

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Gather DNS Service Record Lookup Scan',
				'Description'   => %q{
					Enumerates know SRV Records for a given domaon using target host DNS query tool.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows','linux', 'osx', 'bsd', 'solaris' ],
				'SessionTypes'  => [ 'meterpreter','shell' ]
			))
		register_options(
			[

				OptString.new('DOMAIN', [true, 'Domain ro perform SRV query against.'])

			], self.class)
	end

	# Run Method for when run command is issued
	def run
		srvrcd = [
			'_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.', '_ldap._tcp.',
			'_test._tcp.', '_sips._tcp.', '_sip._udp.', '_sip._tcp.', '_aix._tcp.',
			'_aix._tcp.', '_finger._tcp.', '_ftp._tcp.', '_http._tcp.', '_nntp._tcp.',
			'_telnet._tcp.', '_whois._tcp.', '_h323cs._tcp.', '_h323cs._udp.',
			'_h323be._tcp.', '_h323be._udp.', '_h323ls._tcp.',
			'_h323ls._udp.', '_sipinternal._tcp.', '_sipinternaltls._tcp.',
			'_sip._tls.', '_sipfederationtls._tcp.', '_jabber._tcp.',
			'_xmpp-server._tcp.', '_xmpp-client._tcp.', '_imap.tcp.',
			'_certificates._tcp.', '_crls._tcp.', '_pgpkeys._tcp.',
			'_pgprevokations._tcp.', '_cmp._tcp.', '_svcp._tcp.', '_crl._tcp.',
			'_ocsp._tcp.', '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
			'_hkps._tcp.', '_jabber._udp.','_xmpp-server._udp.', '_xmpp-client._udp.',
			'_jabber-client._tcp.', '_jabber-client._udp.','_kerberos.tcp.dc._msdcs.',
			'_ldap._tcp.ForestDNSZones.'
		]

		domain = datastore['DOMAIN']

		print_status("Performing DNS SRV Record Lookup for Domain #{domain}")

		i, a = 0, []


		if session.type =~ /shell/
			# Only one thread possible when shell
			thread_num = 1
		else
			# When Meterpreter the safest thread number is 10
			thread_num = 10
		end


		srvrcd.each do |srv|
			# Set count option for ping command
			plat = session.platform
			case plat
			when /win/i
				ns_opt = " -query=srv #{srv}#{domain}"
				cmd = "nslookup"
			when /solaris/i
				ns_opt = " -t srv #{srv}#{domain}"
				cmd = "/usr/sbin/host"
			else
				ns_opt = " -t srv #{srv}#{domain}"
				cmd = "/usr/bin/host"
			end

			if i <= thread_num
				a.push(::Thread.new {
						r = cmd_exec(cmd, ns_opt)

						case plat
						when /win/
							if r =~ /\s*internet\saddress\s\=\s/
								nslookup_srv_consume("#{srv}#{domain}", r).each do |f|
									print_status("\t#{f[:srv]} #{f[:target]} #{f[:port]} #{f[:ip]}")
								end
							end
						else
							found = host_srv_consume(r)
							if found
								found.each do |f|
									print_status("\t#{f[:srv]} #{f[:target]} #{f[:port]} #{f[:ip]}")
								end
							end
						end

					})
				i += 1
			else
				sleep(0.05) and a.delete_if {|x| not x.alive?} while not a.empty?
				i = 0
			end
		end
		a.delete_if {|x| not x.alive?} while not a.empty?

	end


	def nslookup_srv_consume(srv,ns_out)
		srv_records = []
		records = ns_out.split(srv)

		# Get host to IP mapping
		ip_map = {}
		records.last.each_line do |e|
			if e =~ /internet\saddress/i
				host,ip = e.split(/\s*internet\saddress\s\=\s/)
				ip_map[host.strip] = ip.strip
			end
		end

		# Get SRV parameter for each record
		records.each do |r|
			if r =~ /svr hostname/
				rcrd ={}
				rcrd[:srv] = srv
				rcrd[:port] = r.scan(/port\s*=\s(\d*)/).join
				rcrd[:target] = r.scan(/svr hostname\s*=\s(\S*)/).join
				if not Rex::Socket.dotted_ip?(rcrd[:target])
					w_get_ip(rcrd[:target]).each do |i|
						rcrd[:ip] = i
						report_host(:host => rcrd[:ip].strip, :name => rcrd[:target])

						# Report on the service found
						srv_info = rcrd[:srv].scan(/^_(\S*)\._(\w*)\./)[0]

						report_service(:host=> rcrd[:ip].strip,
							:port => rcrd[:port].to_i,
							:proto => srv_info[1],
							:name => srv_info[0],
							:host_name => rcrd[:target]
						)
						srv_records << rcrd
					end
				else

					rcrd[:ip] = ip_map[rcrd[:target]]
					# Report hosts found
					report_host(:host => rcrd[:ip].strip, :name => rcrd[:target])

					# Report on the service found
					srv_info = rcrd[:srv].scan(/^_(\S*)\._(\w*)\./)[0]

					report_service(:host=> "1.2.3.4",
						:port => rcrd[:port].to_i,
						:proto => srv_info[1],
						:name => srv_info[0],
						:host_name => rcrd[:target]
					)
					srv_records << rcrd
				end
			end
		end
		return srv_records
	end

	# Get I{ for a given host using host, returns array
	def get_ip(host)
		ip_add = []
		cmd_exec("host"," #{host}").each_line do |l|
			ip =""
			ip = l.scan(/has address (\S*)$/).join
			ip_add << ip if ip != ""
		end
		return ip_add
	end

	# Get IP for given host with nslookup, return array
	def w_get_ip(host)
		ips =[]
		data = cmd_exec("nslookup #{host}")
		if data =~ /Name/
			# Remove unnecessary data and get the section with the addresses
			returned_data = data.split(/Name:/)[1]
			# check each element of the array to see if they are IP
			returned_data.gsub(/\r\n\t |\r\n|Aliases:|Addresses:|Address:/," ").split(" ").each do |e|
				if Rex::Socket.dotted_ip?(e)
					ips << e
				end
			end
		end
		return ips
	end

	def host_srv_consume(host_out)
		srv_records = []
		# Parse for SRV Records
		host_out.each_line do |l|
			if l =~ /has SRV/
				record,port,target = l.scan(/(\S*) has SRV record \d*\s\d*\s(\d*)\s(\S*)/)[0]
				if Rex::Socket.dotted_ip?(target)
					rcrd ={}
					rcrd[:srv] = record
					rcrd[:port] = port
					rcrd[:target] = target
					rcrd[:ip] = target
					srv_records << rcrd

					# Report hosts found
					report_host(:host => rcrd[:ip], :name => rcrd[:target])

					# Report on the service found
					srv_info = rcrd[:srv].scan(/^_(\S*)\._(\w*)\./)[0]
					report_service(:host=> rcrd[:ip],
							:port => rcrd[:port],
							:proto => srv_info[1],
							:name => srv_info[0],
							:host_name => rcrd[:target]
						)
				else
					get_ip(target).each do |i|
						rcrd ={}
						rcrd[:srv] = record
						rcrd[:port] = port
						rcrd[:target] = target
						rcrd[:ip] = i
						srv_records << rcrd

						# Report hosts found
						report_host(:host => rcrd[:ip], :name => rcrd[:target])

						# Report on the service found
						srv_info = rcrd[:srv].scan(/^_(\S*)\._(\w*)\./)[0]
						report_service(:host=> rcrd[:ip],
								:port => rcrd[:port].to_i,
								:proto => srv_info[1],
								:name => srv_info[0],
								:host_name => rcrd[:target]
							)
					end
				end
			end
		end
		return srv_records
	end
end
