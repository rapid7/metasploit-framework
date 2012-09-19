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


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Multi Gather DNS Reverse Lookup Scan',
				'Description'   => %q{
					Performs DNS reverse lookup using the OS included DNS query command.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows','linux', 'osx', 'bsd', 'solaris' ],
				'SessionTypes'  => [ 'meterpreter','shell' ]
			))
		register_options(
			[

				OptAddressRange.new('RHOSTS', [true, 'IP Range to perform reverse lookup against.'])

			], self.class)
	end

	# Run Method for when run command is issued
	def run
		iprange = datastore['RHOSTS']
		found_hosts = []
		print_status("Performing DNS Reverse Lookup for IP range #{iprange}")
		iplst = []

		i, a = 0, []
		ipadd = Rex::Socket::RangeWalker.new(iprange)
		numip = ipadd.num_ips
		while (iplst.length < numip)
			ipa = ipadd.next_ip
			if (not ipa)
				break
			end
			iplst << ipa
		end

		if session.type =~ /shell/
			# Only one thread possible when shell
			thread_num = 1
		else
			# When Meterpreter the safest thread number is 10
			thread_num = 10
		end


		iplst.each do |ip|
			# Set count option for ping command
			plat = session.platform
			case plat
			when /win/i
				ns_opt = " #{ip}"
				cmd = "nslookup"
			when /solaris/i
				ns_opt = " #{ip}"
				cmd = "/usr/sbin/host"
			else
				ns_opt = " #{ip}"
				cmd = "/usr/bin/host"
			end

			if i <= thread_num
				a.push(::Thread.new {
						r = cmd_exec(cmd, ns_opt)

						case plat
						when /win/
							if r =~ /(Name)/
								r.scan(/Name:\s*\S*\s/) do |n|
									hostname = n.split(":    ")
									print_good "\t #{ip} is #{hostname[1].chomp("\n")}"
									report_host({
										:host => ip,
										:name => hostname[1].strip,
										:comm => "Discovered thru post reverse DNS lookup"
										})
								end
							else
								vprint_status("#{ip} does not have a Reverse Lookup Record")
							end
						else
							if r !~ /not found/i
								hostname = r.scan(/domain name pointer (\S*)\./).join
								print_good "\t #{ip} is #{hostname}"
								report_host({
										:host => ip,
										:name => hostname.strip,
										:comm => "Discovered thru post reverse DNS lookup"
									})
							else
								vprint_status("#{ip} does not have a Reverse Lookup Record")
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
end
