
module Msf
class Post

module Priv


	#Returns true if user is admin and false if not.
	def is_admin?
		return session.railgun.shell32.IsUserAnAdmin()["return"]
	end

	# Checks if UAC is enabled, if it is enabled it will return true y running as
	# system or disabled it will return false also if running on a system that does
	# not have UAC it will return false.
	def is_uac_enabled?
		uac = false
		winversion = session.sys.config.sysinfo['OS']

		if winversion =~ /Windows (Vista|7)/
			if session.sys.config.getuid != "NT AUTHORITY\\SYSTEM"
				begin
					key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',KEY_READ)

					if key.query_value('EnableLUA').data == 1
						uac = true
					end

					key.close
				rescue::Exception => e
					print_error("Error Checking UAC: #{e.class} #{e}")
				end
			end
		end
		return uac
	end

end
end
end