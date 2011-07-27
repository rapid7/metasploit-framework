##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::Priv
	include Msf::Post::Common
	

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather USB Drive History',
				'Description'   => %q{ This module will enumerate USB Drive history on a target host.},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'nebulus'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

	end

	# Run Method for when run command is issued
	def run
		print_status("Running module against #{sysinfo['Computer']}")
		# Cache it so as to make it just a bit faster
		isadmin = is_admin?

		# enumerate disks for potentially tying to a drive letter later
		@drives = enum_disks()
		out = "\n"

		@drives.each do |u, v|
			out << sprintf("%5s\t%75s\n", v, u)
		end

		print_status(out)

		usb_drive_classes = registry_enumkeys('HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR')
		usb_uids_to_info = {}

		if usb_drive_classes
			usb_drive_classes.each do |x|
				if x
					registry_enumkeys(x).each do |y|
						begin
							vals = registry_enumvals(y)
							# enumerate each USB device used on the system
							usb_uids_to_info.store(x.match(/HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\(.*)$/)[1], vals)
						rescue
						end
					end
				end
			end
		end

		usb_uids_to_info.each do |u, v|

			guid = '##?#USBSTOR#' << u << '#' << '{53f56307-b6bf-11d0-94f2-00a0c91efb8b}'
			out = "#{v['FriendlyName']}\n" << "="*85 << "\n"
			if isadmin
				keytime = ::Time.at(registry_getkeylastwritetime('HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\' << guid))
				out << sprintf("%25s\t%50s\n", "Disk lpftLastWriteTime", keytime)
			end
			if( not v.key?('ParentIdPrefix') )
				print_status(info_hash_to_str(out, v))
				next
			end
			guid =	'##?#STORAGE#RemoveableMedia#' << v['ParentIdPrefix'] << '&RM#' << '{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'
			if isadmin
				keytime = ::Time.at(registry_getkeylastwritetime('HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}\\' << guid))
				out << sprintf("%25s\t%50s\n", "Volume lpftLastWriteTime", keytime)
			end
			print_status(info_hash_to_str(out, v))
		end

	end

	#-------------------------------------------------------------------------------
	# Function for querying the registry key for the last write time
	#    key_str		Full string representation of the key to be queried
	#    returns		unix timestamp in relation to epoch
	def registry_getkeylastwritetime(key_str = nil)
		return nil if(! key_str)


		# RegQueryInfoKey - http://msdn.microsoft.com/en-us/library/ms724902%28v=vs.85%29.aspx
		# last argument is PFILETIME lpftLastWriteTime, two DWORDS

		#PFILETIME - http://msdn.microsoft.com/en-us/library/ms724284%28v=vs.85%29.aspx, two DWORDS   DWORD dwLowDateTime; DWORD dwHighDateTime;
		#   can use Rex::Proto::SMB::Utils.time_smb_to_unix to convert to unix epoch

		r, b = session.sys.registry.splitkey(key_str)
		key = session.sys.registry.open_key(r, "#{b}", KEY_READ)
		mytime = session.railgun.advapi32.RegQueryInfoKeyA(key.hkey, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, 8)['lpftLastWriteTime']
		key.close
		lo,hi = mytime.unpack('V2')
		return Rex::Proto::SMB::Utils.time_smb_to_unix(hi,lo)
	end

	
	def enum_disks()

		r, b = session.sys.registry.splitkey('HKLM\\SYSTEM\\MountedDevices')
		key = session.sys.registry.open_key(r, "#{b}", KEY_READ)

		ret = {}

		values = key.enum_value
		values.each do |x|
			next if not x.name =~ /\\DosDevices\\/
			name = x.name
			name = name.gsub('\\DosDevices\\', '')
			value = x.query
			if(value[0..0] != '\\')
				str = ''
				tmp = value.unpack('V')
				tmp.each do |x|
					str << "Disk #{x.to_s(16)} "
				end
				ret.store(str, name)
			else
				tmp = x.query
				tmp.gsub!(/\\/, '')
				tmp.gsub!(/\?/, '')
				ret.store(tmp, name)
			end
		end
		key.close
		return ret
	end

	def info_hash_to_str(str, hash)

		out = str
		out << sprintf("%25s\t%50s\n", "Manufacturer", hash['Mfg'])

		if(hash.key?('ParentIdPrefix') )
			mounted_as = nil

			@drives.each do |x, y|
				# go through mounted drives and see if this volume is mounted
				next if not x =~ /\#/						# truncated disk volume that doesnt apply to removable media
				tmp = x.split(/\#/)[2].gsub!(/\x00/, '')			# ParentIdPrefix will be 3rd item, trip internal \x00
				tmp.gsub!(/\&RM$/i, '')		# get rid of RM on end if its there
				mounted_as = y if(tmp.downcase == hash['ParentIdPrefix'].downcase )
			end

			if(mounted_as)
				out << sprintf("%25s\t%50s (%5s)\n", "ParentIdPrefix", hash['ParentIdPrefix'], mounted_as)
			else
				out << sprintf("%25s\t%50s\n", "ParentIdPrefix", hash['ParentIdPrefix'])
			end
		end

		out << sprintf("%25s\t%50s\n", "Class", hash['Class'])
		out << sprintf("%25s\t%50s\n", "Driver", hash['Driver'])
		return out
	end

end