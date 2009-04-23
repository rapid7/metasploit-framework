##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	
	def initialize(info = {})
		super(update_info(info,	
			'Name'   		=> 'HTTP SOAP Verb/Noun Brute Force Scanner',
			'Description'	=> %q{
				This module attempts to brute force SOAP/XML requests to uncover
				hidden methods.
					
			},
			'Author' 		=> [ 'patrick' ],
			'License'		=> MSF_LICENSE,
			'Version'		=> '$Revision$'))   
			
		register_options(
			[
				OptString.new('PATH', [ true,  "The path to test", '/']),
				OptString.new('XMLNAMESPACE', [ true,  "XML Web Service Namespace", 'http://tempuri.org/']),
				OptString.new('XMLINSTANCE', [ true,  "XML Schema Instance", 'http://www.w3.org/2001/XMLSchema-instance']),
				OptString.new('XMLSCHEMA', [ true,  "XML Schema", 'http://www.w3.org/2001/XMLSchema']),
				OptString.new('XMLSOAP', [ true,  "XML SOAP", 'http://schemas.xmlsoap.org/soap/envelope/']),
				OptString.new('CONTENTTYPE', [ true,  "The HTTP Content-Type Header", 'application/x-www-form-urlencoded']),
			], self.class)

	end

	# Fingerprint a single host
	def run_host(ip)

		verbs = [
				'get',
				'active',
				'create',
				'change',
				'set',
				'put',
				'do',
				'go',
				'resolve',
				'start',
				'recover',
				'initiate',
				'negotiate',
				'define',
				'stop',
				'begin',
				'end',
				'manage',
				'administer',
				'modify',
				'register',
				'log',
				'add',
				#'delete', # Best to be safe!
			]
			
		nouns = [
				'password',
				'task',
				'pass',
				'administration',
				'account',
				'admin',
				'login',
				'token',
				'credentials',
				'credential',
				'key',
				'guid',
				'message',
				'user',
				'username',
				'load',
				'list',
				'name',
				'file',
				'path',
				'directory',
				'configuration',
				'config',
				'setting',
				'settings',
				'registry',
				'on',
				'off',
			]

		target_port = datastore['RPORT']
		vhost = datastore['VHOST'] || datastore['RHOST'] || target_host

		begin
			# Check service exists
			res = send_request_raw({
				'uri'          => datastore['PATH'],
				'method'       => 'GET',
				'vhost'         => vhost,
			}, 10)
			
			if (res.code == 200)
				print_status("PATH appears to be OK.")
				
				verbs.each do |v|
					nouns.each do |n|
					
						# This could be cleaned up - patrickw
						data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
						data << '<soap:Envelope xmlns:xsi="' + datastore['XMLINSTANCE'] + '" xmlns:xsd="' + datastore['XMLSCHEMA'] + '" xmlns:soap="' + datastore['XMLSOAP'] + '">' + "\r\n"
						data << '<soap:Body>' + "\r\n"
						data << "<#{v}#{n}" + " xmlns=\"#{datastore['XMLNAMESPACE']}\">" + "\r\n"
						data << "</#{v}#{n}>" + "\r\n"
						data << '</soap:Body>' + "\r\n"
						data << '</soap:Envelope>' + "\r\n\r\n"
						
						res = send_request_raw({
							'uri'          => datastore['PATH'] + '/' + v + n,
							'method'       => 'POST',
							'vhost'         => vhost,
							'data'		=> data,
							'headers' =>
								{
									'Content-Length' => data.length,
									'SOAPAction'	=> '"' + datastore['XMLNAMESPACE'] + v + n + '"',
									'Expect'	=> '100-continue',
									'Content-Type'	=> datastore['CONTENTTYPE'],
								}
						}, 15)
						
						
						if (res.body =~ /method name is not valid/)
							print_status("Server rejected SOAPAction: #{v}#{n} with HTTP: #{res.code} #{res.message}.")
						elsif (res.message =~ /Cannot process the message because the content type/)
							print_status("Server rejected CONTENTTYPE: HTTP: #{res.code} #{res.message}.")
							res.message =~ /was not the expected type\s\'([^']+)'/
							print_status("Set CONTENTTYPE to \"#{$1}\"")
							return false
						else
							print_status("Server responded to SOAPAction: #{v}#{n} with HTTP: #{res.code} #{res.message}.")
							print_status("The HTML content follows:")
							print_status(res.body + "\r\n")
						end
						
					end
				end

		else
			print_status("Server did not respond with 200 OK.")
			print_status(res.to_s)
		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
end
