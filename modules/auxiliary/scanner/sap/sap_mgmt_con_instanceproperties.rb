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

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'SAP Management Console Instance Properties',
			'Version'      => '$Revision$',
			'Description'  => %q{ This module simply attempts to identify the instance properties through the SAP Management Console SOAP Interface. },
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
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request",
				'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
			], self.class)
		register_autofilter_ports([ 50013 ])
		deregister_options('RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'      => "/#{datastore['URI']}",
			'method'   => 'GET',
			'headers' =>
				{
					'User-Agent' => datastore['UserAgent']
				}
		}, 25)
		return if not res

		enum_instance(ip)
	end

	def enum_instance(rhost)
		verbose = datastore['VERBOSE']
		print_status("[SAP] Connecting to SAP Management Console SOAP Interface on #{rhost}:#{rport}")
		success = false
		soapenv='http://schemas.xmlsoap.org/soap/envelope/'
		xsi='http://www.w3.org/2001/XMLSchema-instance'
		xs='http://www.w3.org/2001/XMLSchema'
		sapsess='http://www.sap.com/webas/630/soap/features/session/'
		ns1='ns1:GetInstanceProperties'

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
		data << '<SOAP-ENV:Header>' + "\r\n"
		data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
		data << '<enableSession>true</enableSession>' + "\r\n"
		data << '</sapsess:Session>' + "\r\n"
		data << '</SOAP-ENV:Header>' + "\r\n"
		data << '<SOAP-ENV:Body>' + "\r\n"
		data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"></' + ns1 + '>' + "\r\n"
		data << '</SOAP-ENV:Body>' + "\r\n"
		data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

		begin
			res = send_request_raw({
				'uri'      => "/#{datastore['URI']}",
				'method'   => 'POST',
				'data'     => data,
				'headers'  =>
					{
						'Content-Length' => data.length,
						'SOAPAction'     => '""',
						'Content-Type'   => 'text/xml; charset=UTF-8',
					}
			}, 15)

			if res.code == 200
				body = res.body
				if body.match(/<property>CentralServices<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					centralservices = "#{$1}"
					success = true
				end
				if body.match(/<property>SAPSYSTEM<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					sapsystem = "#{$1}"
					success = true
				end
				if body.match(/<property>SAPSYSTEMNAME<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					sapsystemname = "#{$1}"
					success = true
				end
				if body.match(/<property>SAPLOCALHOST<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					saplocalhost = "#{$1}"
					success = true
				end
				if body.match(/<property>INSTANCE_NAME<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					instancename = "#{$1}"
					success = true
				end
				if body.match(/<property>ICM<\/property><propertytype>NodeURL<\/propertytype><value>([^<]+)<\/value>/)
					icmurl = "#{$1}"
					success = true
				end
				if body.match(/<property>ABAP DB Connection<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					dbstring = "#{$1}"
					success = true
				end
				if body.match(/<property>protectedweb Webmethods<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					protectedweb = "#{$1}"
					success = true
				end
			elsif res.code == 500
				case res.body
				when /<faultstring>(.*)<\/faultstring>/i
					faultcode = "#{$1}"
					fault = true
				end
			end

		rescue ::Rex::ConnectionError
			print_error("[SAP] Unable to attempt authentication")
			return :abort
		end

		if success
			print_good("[SAP] Instance Properties Extracted from #{rhost}:#{rport}")
			if centralservices
				print_good("Central Services: #{centralservices}")
			end
			if sapsystem
				print_good("SAP System Number: #{sapsystem}")
				report_note(:host => '#{rhost}',
							:proto => 'SOAP',
							:port => '#{rport}',
							:type => 'SAP',
							:data => "SAP System Number: #{sapsystem}")
			end
			if sapsystemname
				print_good("SAP System Name: #{sapsystemname}")
				report_note(:host => '#{rhost}',
							:proto => 'SOAP',
							:port => '#{rport}',
							:type => 'SAP',
							:data => "SAP System Name: #{sapsystemname}")
			end
			if saplocalhost
				print_good("SAP Localhost: #{saplocalhost}")
				report_note(:host => '#{rhost}',
						:proto => 'SOAP',
						:port => '#{rport}',
						:type => 'SAP',
						:data => "SAP Localhost: #{saplocalhost}")
			end
			if instancename
				print_good("Instance Name: #{instancename}")
				report_note(:host => '#{rhost}',
						:proto => 'SOAP',
						:port => '#{rport}',
						:type => 'SAP',
						:data => "SAP Instance Name: #{instancename}")
			end
			if icmurl
				print_good("ICM URL: #{icmurl}")
				report_note(:host => '#{rhost}',
							:proto => 'SOAP',
							:port => '#{rport}',
							:type => 'SAP',
							:data => "SAP ICM URL: #{icmurl}")
			end

			if dbstring
				print_good("DATABASE: #{dbstring}")
				report_note(:host => '#{rhost}',
							:proto => 'SOAP',
							:port => '#{rport}',
							:type => 'SAP',
							:data => "SAP dbstring: #{dbstring}")
			end

			if protectedweb
				print_good("protectedweb Webmethods: #{protectedweb}")
			end
			return
		elsif fault
			print_error("[SAP] Errorcode: #{faultcode}")
			return
		else
			print_error("[SAP] failed to identify instance properties")
			return
		end
	end
end
