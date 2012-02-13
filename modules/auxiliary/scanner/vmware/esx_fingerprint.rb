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
require 'msf/core/exploit/vim_soap'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::VIMSoap
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'           => 'VMWare Screenshot Stealer',
			'Version'        => '$Revision$',
			'Description'    => %Q{
							This module accesses the web API interfaces for VMware ESX/ESXi servers
							and attempts to identify version information for that server.},
			'Author'         => ['TheLightCosine <thelightcosine[at]metasploit.com>'],
			'License'        => MSF_LICENSE
		)

		register_options([Opt::RPORT(443)], self.class)
	end


	def run_host(ip)
				soap_data = 
			%Q|<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
			<env:Body>
			<RetrieveServiceContent xmlns="urn:vim25">
				<_this type="ServiceInstance">ServiceInstance</_this>
			</RetrieveServiceContent>
			</env:Body>
			</env:Envelope>|
		datastore['URI'] ||= "/sdk"
		user = Rex::Text.rand_text_alpha(8)
		pass = Rex::Text.rand_text_alpha(8)
		res = nil
		begin
			res = send_request_cgi({
				'uri'     => datastore['URI'],
				'method'  => 'POST',
				'agent'   => 'VMware VI Client',
				'data' =>  soap_data
			}, 25)
		rescue ::Rex::ConnectionError => e
			vprint_error("http://#{ip}:#{rport}#{datastore['URI']} - #{e}")
			return false
		rescue
			vprint_error("Skipping #{ip} due to error - #{e}")
			return false
		end
		fingerprint_vmware(ip,res)
	end

	def fingerprint_vmware(ip,res)
		if res
			return false unless res.body.include?('<vendor>VMware, Inc.</vendor>')
			os_match = res.body.match(/<name>([\w\s]+)<\/name>/)
			ver_match = res.body.match(/<version>([\w\s\.]+)<\/version>/)
			build_match = res.body.match(/<build>([\w\s\.\-]+)<\/build>/)
			full_match = res.body.match(/<fullName>([\w\s\.\-]+)<\/fullName>/)
			this_host = nil
			if os_match and ver_match and build_match and full_match 
				if os_match[1] =~ /ESX/
					this_host = report_host( :host => ip, :os_name => os_match[1], :os_flavor => ver_match[1], :os_sp => "Build #{build_match[1]}" )
				end
			end
			if full_match
				framework.db.sync if this_host
				print_good "Identified #{full_match[1]}"
				report_service(:host => ip, :port => rport, :proto => 'tcp', :sname => 'https', :info => full_match[1])
				return true
			else
				vprint_error("http://#{ip}:#{rport} - Could not identify as VMWare")
				return false
			end
		else
			vprint_error("http://#{ip}:#{rport} - No response")
		end

	end



end

