##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super(update_info(info,
			'Name'           => 'Windows Gather Hardware Enumeration',
			'Description'    => %q{
					Enumerate PCI hardware information from the registry. Please note this script
				will run through registry subkeys such as: 'PCI', 'ACPI', 'ACPI_HAL', 'FDC', 'HID',
				'HTREE', 'IDE', 'ISAPNP', 'LEGACY'', LPTENUM', 'PCIIDE', 'SCSI', 'STORAGE', 'SW',
				and 'USB'; it will take time to finish. It is recommended to run this module as a
				background job.
				},
			'License'        => MSF_LICENSE,
			'Author'         => [ 'Brandon Perry <bperry.volatile[at]gmail.com>' ],
			'Platform'       => [ 'win' ],
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
				"Manufacturer",
				"Extra",
			])

		keys = [
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\PCI\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\ACPI\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\ACPI_HAL\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\FDC\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\HID\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\HTREE\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\IDE\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\ISAPNP\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\LEGACY\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\LPTENUM\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\PCIIDE\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\Root\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\SCSI\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\STORAGE\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\SW\\",
			"HKLM\\SYSTEM\\ControlSet001\\Enum\\USB\\",
		]

		keys.each do |key|
			devices = registry_enumkeys(key)

			t = []

			while(not devices.nil? and not devices.empty?)
				1.upto(3) do
					t << framework.threads.spawn("Module(#{self.refname})", false, devices.shift) do |device|
						next if device.nil?
						vprint_status("Enumerating #{device}")

						infos = registry_enumkeys(key + "\\" + device)
						next if infos.nil?

						infos.each do |info|
							next if info.nil?

							info_key = key + "\\" + device + "\\" + info

							desc         = registry_getvaldata(info_key, "DeviceDesc")
							mfg          = registry_getvaldata(info_key, "Mfg")
							device_class = registry_getvaldata(info_key, "Class")
							driver_guid  = registry_getvaldata(info_key, "Driver")
							extra        = ""

							if key =~ /USB/ or key =~ /LPTENUM/
								extra = registry_getvaldata(info_key, "LocationInformation")
							end

							if key =~ /SCSI/ or key =~ /\\IDE/ or key =~ /ACPI\\/
								extra = registry_getvaldata(info_key, "FriendlyName")
							end

							desc = desc.split(';')[1] if desc =~ /^@/
							mfg = mfg.split(';')[1] if mfg =~ /^@/

							desc         = '' if desc.nil?
							mfg          = '' if mfg.nil?
							device_class = '' if device_class.nil?
							driver_guid  = '' if driver_guid.nil?
							extra        = '' if extra.nil?

							next if desc.empty? and mfg.empty?

							driver_version = ""

							if not driver_guid.nil? or not driver_guid.empty?
								if driver_guid =~ /\\/
									k = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\" + driver_guid
									d = registry_getvaldata(k, "DriverVersion")
									driver_version << d if not d.nil?
								end
							end

							done = false

							tbl.rows.each do |row|
								if row[0] == desc and
									row[1] == driver_version and
									row[2] == device_class and
									row[3] == mfg and
									row[4] == extra
									done = true
									break
								end
							end

							tbl << [desc, driver_version, device_class, mfg, extra] if not done
						end
					end
					t.map {|x| x.join }
				end
			end
		end

		results = tbl.to_s
		vprint_line("\n" + results)

		path = store_loot("host.hardware", "text/plain", session, results, "hardware.txt", "Host Hardware")
		print_status("Results saved in: #{path}")
	end

	def run
		print_status("Enumerating hardware on #{sysinfo['Computer']}")
		begin
			list
		rescue ::Exception => e
			if e.to_s =~ /execution expired/i
				print_error("Sorry, execution expired. Module could not finish running.")
			else
				print_error("An unexpected error has occurred: #{e.to_s}:\n#{e.backtrace}")
			end
		end
	end
end
