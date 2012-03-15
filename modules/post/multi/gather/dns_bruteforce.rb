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
				'Name'          => 'Multi Gather DNS Forward Lookup Bruteforce',
				'Description'   => %q{
					Brute force subdomains and hostnames via wordlist.
				},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows','linux', 'osx', 'bsd', 'solaris' ],
				'SessionTypes'  => [ 'meterpreter','shell' ]
			))
		register_options(
			[

				OptString.new('DOMAIN', [true, 'Domain to do a fordward lookup bruteforce against.']),
				OptPath.new('NAMELIST',[true, "List of hostnames or subdomains to use.",
						::File.join(Msf::Config.install_root, "data", "wordlists", "namelist.txt")])

			], self.class)
	end

	# Run Method for when run command is issued
	def run

		domain = datastore['DOMAIN']
		hostlst = datastore['NAMELIST']
		i, a = 0, []

		print_status("Performing DNS Forward Lookup Bruteforce for Domain #{domain}")
		if session.type =~ /shell/
			# Only one thread possible when shell
			thread_num = 1
		else
			# When Meterpreter the safest thread number is 10
			thread_num = 10
		end

		if ::File.exists?(hostlst)
			::File.open(hostlst).each do |n|
				# Set count option for ping command
				plat = session.platform
				case plat
				when /win/i
					ns_opt = " #{n.strip}.#{domain}"
					cmd = "nslookup"
				when /solaris/i
					ns_opt = " #{n.strip}.#{domain}"
					cmd = "/usr/sbin/host"
				else
					ns_opt = " #{n.strip}.#{domain}"
					cmd = "/usr/bin/host"
				end

				if i <= thread_num
					print_status("Trying #{ns_opt}")
					a.push(::Thread.new {
							r = cmd_exec(cmd, ns_opt)

							case session.platform
							when /win/
								proccess_win(r,ns_opt)
							else
								process_nix(r,ns_opt)
							end

						})
					i += 1
				else
					sleep(2.0) and a.delete_if {|x| not x.alive?} while not a.empty?
					i = 0
				end
			end
			a.delete_if {|x| not x.alive?} while not a.empty?
		else
			print_error("Name list file specified does not exist.")
		end

	end

	# Process the data returned by nslookup
	def proccess_win(data,ns_opt)
		if data =~ /Name/
			# Remove unnecessary data and get the section with the addresses
			returned_data = data.split(/Name:/)[1]
			# check each element of the array to see if they are IP
			returned_data.gsub(/\r\n\t |\r\n|Aliases:|Addresses:/," ").split(" ").each do |e|
				if Rex::Socket.dotted_ip?(e)
					print_status("#{ns_opt} #{e}")
					report_host(:host=>e, :name=>ns_opt.strip)
				end
			end
		end
	end

	# Process the data returned by the host command
	def process_nix(r,ns_opt)
		r.each_line do |l|
			data = l.scan(/(\S*) has address (\S*)$/)
			if not data.empty?
				data.each do |e|
					print_good("#{ns_opt} #{e[1]}")
					report_host(:host=>e[1], :name=>ns_opt.strip)
				end
			end
		end
	end
end
