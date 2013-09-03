##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::SNMPClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'SNMP Set Module',
			'Description' => %q{
					This module, similar to snmpset tool, uses the SNMP SET request
					to set information on a network entity. A OID (numeric notation)
					and a value are required. Target device must permit write access.
			},
			'References'  =>
				[
					[ 'URL', 'http://en.wikipedia.org/wiki/Simple_Network_Management_Protocol' ],
					[ 'URL', 'http://www.net-snmp.org/docs/man/snmpset.html' ],
					[ 'URL', 'http://www.oid-info.com/' ],
				],
			'Author'      => 'Matteo Cantoni <goony[at]nothink.org>',
			'License'     => MSF_LICENSE
		))

		register_options([
			OptString.new('OID', [ true, "The object identifier (numeric notation)"]),
			OptString.new('OIDVALUE', [ true, "The value to set"]),
		], self.class)
	end

	def run_host(ip)

		begin

			oid      = datastore['OID'].to_s
			oidvalue = datastore['OIDVALUE'].to_s
			comm     = datastore['COMMUNITY'].to_s

			snmp = connect_snmp

			print_status("Try to connect to #{ip}...")

			# get request
			check = snmp.get_value(oid)

			if check.to_s =~ /Null/
				check = '\'\''
			end

			print_status("Check initial value : OID #{oid} => #{check}")

			# set request
			varbind = SNMP::VarBind.new(oid,SNMP::OctetString.new(oidvalue))
			resp = snmp.set(varbind)

			if resp.error_status == :noError

				print_status("Set new value : OID #{oid} => #{oidvalue}")

				# get request
				check = snmp.get_value(oid)

				if check.to_s =~ /Null/
					check = '\'\''
				end

				print_status("Check new value : OID #{oid} => #{check}")

			else
				print_status("#{ip} - OID not writable or does not provide WRITE access with community '#{comm}'")
			end

		rescue ::SNMP::RequestTimeout
			print_error("#{ip} - SNMP request timeout with community '#{comm}'.")
		rescue ::Rex::ConnectionError
			print_error("#{ip} - 'Connection Refused'")
		rescue SNMP::UnsupportedVersion
			print_error("#{ip} - Unsupported SNMP version specified. Select from '1' or '2c'.")
		rescue ::Interrupt
			raise $!
		rescue ::Exception => e
			print_error("#{ip} Error: #{e.class} #{e} #{e.backtrace}")
		ensure
			disconnect_snmp
		end
	end

end
