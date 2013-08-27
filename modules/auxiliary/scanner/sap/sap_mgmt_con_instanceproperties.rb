##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'         => 'SAP Management Console Instance Properties',
			'Description'  => %q{
				This module simply attempts to identify the instance properties
				through the SAP Management Console SOAP Interface.
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
			], self.class)
		register_autofilter_ports([ 50013 ])
		deregister_options('RHOST')
	end

	def rport
		datastore['RPORT']
	end

	def run_host(ip)
		res = send_request_cgi({
			'uri'      => normalize_uri(datastore['URI']),
			'method'   => 'GET'
		}, 25)

		if not res
			print_error("#{rhost}:#{rport} [SAP] Unable to connect")
			return
		end

		enum_instance(ip)
	end

	def enum_instance(rhost)
		print_status("#{rhost}:#{rport} [SAP] Connecting to SAP Management Console SOAP Interface")
		success = false
		soapenv='http://schemas.xmlsoap.org/soap/envelope/'
		xsi='http://www.w3.org/2001/XMLSchema-instance'
		xs='http://www.w3.org/2001/XMLSchema'
		sapsess='http://www.sap.com/webas/630/soap/features/session/'
		ns1='ns1:GetInstanceProperties'

		data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
		data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi
		data << '" xmlns:xs="' + xs + '">' + "\r\n"
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
				'uri'      => normalize_uri(datastore['URI']),
				'method'   => 'POST',
				'data'     => data,
				'headers'  =>
					{
						'Content-Length' => data.length,
						'SOAPAction'     => '""',
						'Content-Type'   => 'text/xml; charset=UTF-8',
					}
			}, 15)

			if res.nil?
				print_error("#{rhost}:#{rport} [SAP] Unable to connect")
				return
			end

			if res.code == 200
				body = res.body
				if body.match(/<property>CentralServices<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					centralservices = $1.strip
					success = true
				end
				if body.match(/<property>SAPSYSTEM<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					sapsystem = $1.strip
					success = true
				end
				if body.match(/<property>SAPSYSTEMNAME<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					sapsystemname = $1.strip
					success = true
				end
				if body.match(/<property>SAPLOCALHOST<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					saplocalhost = $1.strip
					success = true
				end
				if body.match(/<property>INSTANCE_NAME<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					instancename = $1.strip
					success = true
				end
				if body.match(/<property>ICM<\/property><propertytype>NodeURL<\/propertytype><value>([^<]+)<\/value>/)
					icmurl = $1.strip
					success = true
				end
				if body.match(/<property>IGS<\/property><propertytype>NodeURL<\/propertytype><value>([^<]+)<\/value>/)
					igsurl = $1.strip
					success = true
				end
				if body.match(/<property>ABAP DB Connection<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					dbstring = $1.strip
					success = true
				end
				if body.match(/<property>J2EE DB Connection<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					j2eedbstring = $1.strip
					success = true
				end
				if body.match(/<property>Webmethods<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					webmethods = $1.strip
					success = true
				end
				if body.match(/<property>Protected Webmethods<\/property><propertytype>Attribute<\/propertytype><value>([^<]+)<\/value>/)
					protectedweb = $1.strip
					success = true
				end
			elsif res.code == 500
				case res.body
				when /<faultstring>(.*)<\/faultstring>/i
					faultcode = $1.strip
					fault = true
				end
			end

		rescue ::Rex::ConnectionError
			print_error("#{rhost}:#{rport} [SAP] Unable to connect")
			return
		end

		if success
			print_good("#{rhost}:#{rport} [SAP] Instance Properties Extracted")
			if centralservices
				print_good("#{rhost}:#{rport} [SAP] Central Services: #{centralservices}")
			end
			if sapsystem
				print_good("#{rhost}:#{rport} [SAP] SAP System Number: #{sapsystem}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.sapsystem',
							:data => {:proto => "soap", :sapsystem => sapsystem})
			end
			if sapsystemname
				print_good("#{rhost}:#{rport} [SAP] SAP System Name: #{sapsystemname}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.systemname',
							:data => {:proto => "soap", :sapsystemname => sapsystemname})
			end
			if saplocalhost
				print_good("#{rhost}:#{rport} [SAP] SAP Localhost: #{saplocalhost}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.localhost',
							:data => {:proto => "soap", :saplocalhost => saplocalhost})
			end
			if instancename
				print_good("#{rhost}:#{rport} [SAP] Instance Name: #{instancename}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.instancename',
							:data => {:proto => "soap", :instancename => instancename})
			end
			if icmurl
				print_good("#{rhost}:#{rport} [SAP] ICM URL: #{icmurl}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.icm.url',
							:data => {:proto => "soap", :icmurl => icmurl})
			end
			if igsurl
				print_good("#{rhost}:#{rport} [SAP] IGS URL: #{igsurl}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.igs.url',
							:data => {:proto => "soap", :igsurl => igsurl})
			end
			if dbstring
				print_good("#{rhost}:#{rport} [SAP] ABAP DATABASE: #{dbstring}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.dbstring',
							:data => {:proto => "soap", :dbstring => dbstring},
							:update => :unique_data )
			end
			if j2eedbstring
				print_good("#{rhost}:#{rport} [SAP] J2EE DATABASE: #{j2eedbstring}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.j2eedbstring',
							:data => {:proto => "soap", :j2eedbstring => j2eedbstring},
							:update => :unique_data )
			end
			if protectedweb
				protectedweb_arr = protectedweb.split(",")
				print_good("#{rhost}:#{rport} [SAP] Protected Webmethods (auth required) :::")
				print_status("#{protectedweb}")
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.protected.web.methods',
							:data => {:proto => "soap", :protectedweb => protectedweb},
							:update => :unique_data )
			end
			if webmethods
				webmethods_output = [] # create empty webmethods array
				webmethods_arr = webmethods.split(",")
				print_good("#{rhost}:#{rport} [SAP] Unprotected Webmethods :::")
				webmethods_arr.each do | webm |
					# Only add webmethods not found in protectedweb_arr
					webmethods_output << webm if not protectedweb_arr.include?(webm)
				end
				print_status("#{webmethods_output.join(',')}") if webmethods_output
				report_note(:host => rhost,
							:proto => 'tcp',
							:port => rport,
							:type => 'sap.web.methods',
							:data => {:proto => "soap", :webmethods => webmethods},
							:update => :unique_data )
			end
			return
		elsif fault
			print_error("#{rhost}:#{rport} [SAP] Error code: #{faultcode}")
			return
		else
			print_error("#{rhost}:#{rport} [SAP] Failed to identify instance properties")
			return
		end
	end
end
