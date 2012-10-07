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
require 'pry'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute

	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'WinRM Login Utility',
			'Version'        => '$Revision$',
			'Description'    => 'This module attempts to authenticate to an HTTP service.',
			'References'  =>
				[

				],
			'Author'         => [ 'hdm' ],
			'References'     =>
				[
					[ 'CVE', '1999-0502'] # Weak password
				],
			'License'        => MSF_LICENSE
		)

		register_options(
			[
				OptString.new('AUTH_URI', [ false, "The URI to authenticate against (default:auto)" ])
			], self.class)
		register_autofilter_ports([ 5985,5986 ])
	end

	def target_url
		proto = "http"
		if rport == 5986 or ssl
			proto = "https"
		end
		"#{proto}://#{rhost}:#{rport}#{@uri.to_s}"
	end

	def run_host(ip)
		send_request_cgi({
			'uri'  		=>  '/wsman',
			'method'   	=> 'POST',
			'data'		=> test_request,
		}, 20)


		opts = {
			'uri' => '/wsman',
			'data' => test_request,
			'username' => 'Administrator',
			'password' => 'P@ssw0rd1!'
		}
		resp,c = send_http_auth_ntlm(opts)
		print_status resp.inspect
	end

	def send_http_auth_ntlm(opts={}, timeout = 20)
		#ntlm_message_1 = "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
		ntlm_options = {
				:signing 		=> false,
				:usentlm2_session 	=> datastore['NTLM::UseNTLM2_session'],
				:use_ntlmv2 		=> datastore['NTLM::UseNTLMv2'],
				:send_lm 		=> datastore['NTLM::SendLM'],
				:send_ntlm		=> datastore['NTLM::SendNTLM']
				}

		ntlmssp_flags = NTLM_UTILS.make_ntlm_flags(ntlm_options)
		workstation_name =  Rex::Text.rand_text_alpha(rand(8)+1)
		domain_name = 'MSFLAB'

		ntlm_message_1 = "NEGOTIATE " + Rex::Text::encode_base64(NTLM_UTILS::make_ntlmssp_blob_init( domain_name,
													workstation_name,
													ntlmssp_flags))
		to = opts[:timeout] || timeout
		begin
			c = connect(opts)

			ctype = "application/soap+xml;charset=UTF-8"

			# First request to get the challenge
			r = c.request_cgi(opts.merge({
				'uri' => opts['uri'],
				'method' => 'POST',
				'ctype'     => ctype,
				'headers' => { 'Authorization' => "Negotiate TlRMTVNTUAABAAAAB4IIAA=="},
				'data'        => opts['data']
				}))
			resp = c.send_recv(r, to)
			unless resp.kind_of? Rex::Proto::Http::Response
				return [nil,nil]
			end
			return [nil,nil] if resp.code == 404
			return [nil,nil] unless resp.code == 401 && resp.headers['WWW-Authenticate']

			# Get the challenge and craft the response
			ntlm_challenge = resp.headers['WWW-Authenticate'].match(/NEGOTIATE ([A-Z0-9\x2b\x2f=]+)/i)[1]
			return [nil,nil] unless ntlm_challenge


			#old and simplier method but not compatible with windows 7/2008r2
			#ntlm_message_2 = Rex::Proto::NTLM::Message.decode64(ntlm_challenge)
			#ntlm_message_3 = ntlm_message_2.response( {:user => opts['username'],:password => opts['password']}, {:ntlmv2 => true})

			ntlm_message_2 = Rex::Text::decode_base64(ntlm_challenge)
			blob_data = NTLM_UTILS.parse_ntlm_type_2_blob(ntlm_message_2)

			challenge_key = blob_data[:challenge_key]
			server_ntlmssp_flags = blob_data[:server_ntlmssp_flags] #else should raise an error
			#netbios name
			default_name =  blob_data[:default_name] || ''
			#netbios domain
			default_domain = blob_data[:default_domain] || ''
			#dns name
			dns_host_name =  blob_data[:dns_host_name] || ''
			#dns domain
			dns_domain_name =  blob_data[:dns_domain_name] || ''
			#Client time
			chall_MsvAvTimestamp = blob_data[:chall_MsvAvTimestamp] || ''

			spnopt = {:use_spn => datastore['NTLM::SendSPN'], :name =>  self.rhost}

			resp_lm,
			resp_ntlm,
			client_challenge,
			ntlm_cli_challenge = NTLM_UTILS.create_lm_ntlm_responses(opts['username'], opts['password'], challenge_key,
										domain_name, default_name, default_domain,
										dns_host_name, dns_domain_name, chall_MsvAvTimestamp,
										spnopt, ntlm_options)

			ntlm_message_3 = NTLM_UTILS.make_ntlmssp_blob_auth(domain_name, workstation_name, opts['username'],
										resp_lm, resp_ntlm, '', ntlmssp_flags)
			ntlm_message_3 = Rex::Text::encode_base64(ntlm_message_3)

			# Send the response
			r = c.request_cgi(opts.merge({
				'uri' => opts['uri'],
				'method' => 'POST',
				'ctype'     => ctype,
				'headers' => { 'Authorization' => "NEGOTIATE #{ntlm_message_3}"},
				'data'        => opts['data']
				}))
			resp = c.send_recv(r, to, true)
			unless resp.kind_of? Rex::Proto::Http::Response
				return [nil,nil]
			end
			return [nil,nil] if resp.code == 404
			return [resp,c]

		rescue ::Errno::EPIPE, ::Timeout::Error
		end
	end

	def test_request
		data = %q|<?xml version="1.0" encoding="UTF-8"?><env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:b="http://schemas.dmtf.org/wbem/wsman/1/cimbinding.xsd" xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration" xmlns:x="http://schemas.xmlsoap.org/ws/2004/09/transfer" xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell" xmlns:cfg="http://schemas.microsoft.com/wbem/wsman/1/config"><env:Header><a:To>http://172.16.221.145:5985/wsman</a:To><a:ReplyTo><a:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo><w:MaxEnvelopeSize mustUnderstand="true">153600</w:MaxEnvelopeSize><a:MessageID>uuid:BE2777BF-0AF2-41E5-A15C-E8A4403DEFD8</a:MessageID><w:Locale xml:lang="en-US" mustUnderstand="false"/><p:DataLocale xml:lang="en-US" mustUnderstand="false"/><w:OperationTimeout>PT60S</w:OperationTimeout><w:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/*</w:ResourceURI><a:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate</a:Action></env:Header><env:Body><n:Enumerate><w:OptimizeEnumeration xsi:nil="true"/><w:MaxElements>32000</w:MaxElements><w:Filter Dialect="http://schemas.microsoft.com/wbem/wsman/1/WQL">select Name,Status from Win32_Service</w:Filter></n:Enumerate></env:Body></env:Envelope>|
	end

end
