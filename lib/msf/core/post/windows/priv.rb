# -*- coding: binary -*-

require 'msf/core/post/windows/accounts'

module Msf
class Post
module Windows

module Priv

	include ::Msf::Post::Windows::Accounts

	LowIntegrityLevel = 'S-1-16-4096'
	MediumIntegrityLevel =  'S-1-16-8192'
	HighIntegrityLevel = 'S-1-16-12288'
	SystemIntegrityLevel = 'S-1-16-16384'

	Administrators = 'S-1-5-32-544'

	# http://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx
	# ConsentPromptBehaviorAdmin
	UACNoPrompt = 0
	UACPromptCredsIfSecureDesktop = 1
	UACPromptConsentIfSecureDesktop = 2
	UACPromptCreds = 3
	UACPromptConsent = 4
	UACDefault = 5

	#
	# Returns true if user is admin and false if not.
	#
	def is_admin?
		if session_has_ext
			# Assume true if the OS doesn't expose this (Windows 2000)
			session.railgun.shell32.IsUserAnAdmin()["return"] rescue true
		else
			cmd = "cmd.exe /c reg query HKU\\S-1-5-19"
			results = session.shell_command_token_win32(cmd)
			if results =~ /Error/
				return false
			else
				return true
			end
		end
	end

	#
	# Returns true if in the administrator group
	#
	def is_in_admin_group?
		whoami = get_whoami

		if whoami.nil?
			print_error("Unable to identify admin group membership")
			return nil
		elsif whoami.include? Administrators
			return true
		else
			return false
		end
	end

	#
	# Returns true if running as Local System
	#
	def is_system?
		if session_has_ext
			local_sys = resolve_sid("S-1-5-18")
			if session.sys.config.getuid == "#{local_sys[:domain]}\\#{local_sys[:name]}"
				return true
			else
				return false
			end
		else
			cmd = "cmd.exe /c reg query HKLM\\SAM\\SAM"
			results = session.shell_command_token_win32(cmd)
			if results =~ /Error/
				return false
			else
				return true
			end
		end
	end

	#
	# Returns true if UAC is enabled
	#
	# Returns false if the session is running as system, if uac is disabled or
	# if running on a system that does not have UAC
	#
	def is_uac_enabled?
		uac = false
		winversion = session.sys.config.sysinfo['OS']

		if winversion =~ /Windows (Vista|7|8|2008)/
			unless is_system?
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

	#
	# Returns the UAC Level
	#
	# 2 - Always Notify, 5 - Default, 0 - Disabled
	#
	def get_uac_level
		begin
			open_key = session.sys.registry.open_key(
					HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
					KEY_READ
			)
			uac_level = open_key.query_value('ConsentPromptBehaviorAdmin')
		rescue Exception => e
			print_error("Error Checking UAC: #{e.class} #{e}")
		end
		return uac_level.data
	end

	#
	# Returns the Integrity Level
	#
	def get_integrity_level
		whoami = get_whoami

		if whoami.nil?
			print_error("Unable to identify integrity level")
			return nil
		elsif whoami.include? LowIntegrityLevel
			return LowIntegrityLevel
		elsif whoami.include? MediumIntegrityLevel
			return MediumIntegrityLevel
		elsif whoami.include? HighIntegrityLevel
			return HighIntegrityLevel
		elsif whoami.include? SystemIntegrityLevel
			return SystemIntegrityLevel
		end
	end

	#
	# Returns the output of whoami /groups
	#
	# Returns nil if Windows whoami is not available
	#
	def get_whoami
		whoami = cmd_exec('cmd /c whoami /groups')

		if whoami.nil? or whoami.empty?
			return nil
		elsif whoami =~ /is not recognized/ or whoami =~ /extra operand/ or whoami =~ /Access is denied/
			return nil
		else
			return whoami
		end
	end

	#
	# Return true if the session has extended capabilities (ie meterpreter)
	#
	def session_has_ext
		begin
			return !!(session.railgun and session.sys.config)
		rescue NoMethodError
			return false
		end
	end

end
end
end
end

