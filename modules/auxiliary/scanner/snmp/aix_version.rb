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

	include Msf::Exploit::Remote::SNMPClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name'        => 'AIX SNMP Scanner Auxiliary Module',
			'Version'     => '$Revision$',
			'Description' => 'AIX SNMP Scanner Auxiliary Module',
			'Author'      =>
				[
					'Adriano Lima <adriano@risesecurity.org>',
					'ramon'
				],
			'License'     => MSF_LICENSE
		)

	end

	def run_host(ip)
		begin
			snmp = connect_snmp

			value = snmp.get_value('sysDescr.0')

			if value =~ /AIX/
				value = value.split("\n")
				description = value[0].strip
				value = value[2].split(':')

				value = value[1].strip
				value = value.split('.')

				value[0] = value[0].to_i
				value[1] = value[1].to_i
				value[2] = value[2].to_i
				value[3] = value[3].to_i

				version = "#{value[0]}.#{value[1]}.#{value[2]}.#{value[3]}"

				report_note(
						:host   => ip,
						:proto  => 'SNMP',
						:port   => datastore['RPORT'],
						:type   => 'AIX',
						:data   => version
				)

				status = "#{ip} (#{description}) is running: "
				status << "IBM AIX Version #{value[0]}.#{value[1]}.#{value[3]} "
				status << "(#{version})"

				print_status(status)
			end

			disconnect_snmp

		rescue Exception => e
			puts "#{e.class}, #{e.message}"

		end

	end

end

