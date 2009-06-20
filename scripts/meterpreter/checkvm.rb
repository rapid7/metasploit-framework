#!/usr/bin/env ruby

#Meterpreter script for detecting if target host is a Virtual Machine
#Provided by Carlos Perez at carlos_perez[at]darkoperator.com
#Verion: 0.1.0
################## Variable Declarations ##################
session = client
def chkvm(session)
	check = nil
	info = session.sys.config.sysinfo
	print_status "Checking if #{info['Computer']} is a Virtual Machine ........"

	# Check for Target Machines if running in VM, only fo VMware Workstation/Fusion
	begin
		key = 'HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS'
		root_key, base_key = session.sys.registry.splitkey(key)
		open_key = session.sys.registry.open_key(root_key,base_key,KEY_READ)
		v = open_key.query_value('SystemManufacturer')
		sysmnfg =  v.data.downcase
		if sysmnfg =~ /vmware/
			print_status "\tThis is a VMware Workstation/Fusion Virtual Machine"
			check = 1
		elsif sysmnfg =~ /xen/
			print_status("\tThis is a Xen Virtual Machine.")
			check = 1
		end
	rescue
		print_status("BIOS Check Failed")

	end
	if check != 1
		begin
			#Registry path using the HD and CD rom entries in the registry in case propirtary tools are
			#not installed.
			key2 = "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
			root_key2, base_key2 = session.sys.registry.splitkey(key2)
			open_key2 = session.sys.registry.open_key(root_key2,base_key2,KEY_READ)
			v2 = open_key2.query_value('Identifier')

			if v2.data.downcase =~ /vmware/
				print_status "\tThis is a VMWare virtual Machine"
			elsif v2.data.downcase =~ /vbox/
				print_status "\tThis is a Sun VirtualBox virtual Machine"
			elsif v2.data.downcase =~ /xen/
				print_status "\tThis is a Xen virtual Machine"
			elsif v2.data.downcase =~ /virtual hd/
				print_status "\tThis is a Hyper-V/Virtual Server virtual Machine"
			end
		rescue::Exception => e
			print_status("#{e.class} #{e}")
		end
	end
end
chkvm(session)