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
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Windows PCI Hardware Enumeration',
			'Description'    => %q{ Enumerate PCI hardware information from the registry },
			'License'        => MSF_LICENSE,
			'Version'        => "$Revision$",
			'Author'         => [ 'Brandon Perry' ],
			'Platform'       => [ 'windows' ],
			'SessionTypes'   => [ 'meterpreter' ]
		))
	end

	def list
		tbl = Rex::Ui::Text::Table.new(
			'Header'  => "Device Information",
			'Indent'  => 1,
			'Columns' =>
			[
				"Device Description",
				"Driver Version",
				"Class",
				"Manufacturer"
			])

		keys = [ "HKLM\\SYSTEM\\ControlSet001\\Enum\\PCI\\" ]

		keys.each do |key|
			devices = registry_enumkeys(key)
			next if devices.nil? or devices.empty?

			devices.each do |device|
				next if device.nil?
				print_status("Enumerating #{device}") if datastore['VERBOSE']

				infos = registry_enumkeys(key + "\\" + device)
				next if infos.nil?

				infos.each do |info|
					next if info.nil?
					desc         = registry_getvaldata(key + "\\" + device + "\\" + info, "DeviceDesc")
					mfg          = registry_getvaldata(key + "\\" + device + "\\" + info, "Mfg")
					device_class = registry_getvaldata(key + "\\" + device + "\\" + info, "Class")
					driver_guid  = registry_getvaldata(key + "\\" + device + "\\" + info, "Driver")

					desc         = '' if desc.nil?
					mfg          = '' if mfg.nil?
					device_class = '' if device_class.nil?
					driver_guid  = '' if driver_guid.nil?

					print_status("DeviceDesc: #{desc}") if datastore['VERBOSE']
					print_status("Mfg: #{mfg}") if datastore['VERBOSE']
					print_status("Class: #{device_class}") if datastore['VERBOSE']
					print_status("Driver: #{driver_guid}") if datastore['VERBOSE']

					driver_version = ""
					if not driver_guid.nil? or not driver_guid.empty?
						if driver_guid =~ /\\\\/
							tmp = driver_guid.split('\\')
							k = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\" + tmp[0] + "\\0000"
							driver_version << registry_getvaldata(k, "DriverVersion")
						end
					end

					tbl << [desc, driver_version, device_class, mfg]
				end
			end
		end

		results = tbl.to_s
		print_line("\n" + results) if datastore['VERBOSE']

		path = store_loot("host.hardware", "text/plain", session, results, "hardware.txt", "Host Hardware")
		print_status("Results saved in: #{path}")
	end

	def run
		print_status("Enumerating hardware on #{sysinfo['Computer']}")
		list
	end
end
