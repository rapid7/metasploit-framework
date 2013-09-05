# -*- coding: binary -*-

require 'msf/core/post/windows/accounts'

module Msf::Post::Windows::Priv
	include ::Msf::Post::Windows::Accounts

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

    if winversion =~ /Windows (Vista|7|2008)/
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
