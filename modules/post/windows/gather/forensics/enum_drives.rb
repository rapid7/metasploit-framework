##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

#
# List physical drives and logical volumes on the remote system
#
# R. Wesley McGrew wesley@mcgrewsecurity.com
#    http://mcgrewsecurity.com
# Mississippi State University National Forensics Training Center
#    http://msu-nftc.org

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Gather Physical Drives and Logical Volumes',
			'Description'   => %q{This module will list physical drives and logical volumes},
			'License'       => MSF_LICENSE,
			'Platform'      => ['win'],
			'SessionTypes'  => ['meterpreter'],
			'Author'        => ['Wesley McGrew <wesley[at]mcgrewsecurity.com>']
		))
		register_options(
			[
				OptInt.new('MAXDRIVES',[false,'Maximum physical drive number',10])
			], self.class)
	end

	def print_device(devname)
		ioctl_disk_get_drive_geometry_ex = 0x000700A0
		ioctl_disk_get_partition_info = 0x00074004
		removable = 0x0b
		fixed     = 0x0c
		invalid_handle_value = 0xFFFFFFFF
		result = client.railgun.kernel32.CreateFileA(devname, "GENERIC_READ",
			0x3, nil, "OPEN_EXISTING", 'FILE_ATTRIBUTE_READONLY', 0)
		handle = result['return']
		if result['return'] != invalid_handle_value
			driveinfo = ""
			ioctl = client.railgun.kernel32.DeviceIoControl(handle,ioctl_disk_get_drive_geometry_ex,
				"",0,200,200,4,"")
			if ioctl['GetLastError'] == 6
				ioctl = client.railgun.kernel32.DeviceIoControl(handle,ioctl_disk_get_drive_geometry_ex,
					"",0,200,200,4,"")
			end
			geometry = ioctl['lpOutBuffer']
			if geometry[8] == removable
				type = "Removable"
			elsif geometry[8] == fixed
				type = "Fixed"
			else
				type = ""
			end

			size = geometry[24,31].unpack('Q')
			if size.to_s == "4702111234474983745"
				size = 'N/A'
			end

			print_line("%-25s%12s%15i" % [devname,type,size[0]])
			client.railgun.kernel32.CloseHandle(handle)
		end
	end

	def run
		print_line("Device Name:                    Type:   Size (bytes):")
		print_line("------------                    -----   -------------")
		print_line("<Physical Drives:>")
		max_physical = datastore['MAXDRIVES']
		(0..max_physical).each do |i|
			devname = "\\\\.\\PhysicalDrive#{i}"
			print_device(devname)
		end

		# Props to Rob Fuller (mubix at room362.com) for logical drive enumeration code:
		bitmask = client.railgun.kernel32.GetLogicalDrives()["return"]
		drives = []
		letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		(0..25).each do |i|
			test = letters[i,1]
			rem = bitmask % (2**(i+1))
			if rem > 0
				drives << test
				bitmask = bitmask - rem
			end
		end

		print_line ("<Logical Drives:>")
		drives.each do |i|
			devname = "\\\\.\\#{i}:"
			print_device(devname)
		end
	end

end
