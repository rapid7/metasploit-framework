##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Multi Manage File Compressor',
        'Description'   => %q{
          This module zips a file or a directory. On Linux, it uses the zip command.
          On Windows, it will try to use remote target's 7Zip if found. If not, it falls
          back to its own VBScript.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'sinn3r' ],
        'Platform'      => [ 'win', 'linux' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))

    register_options(
      [
        OptString.new('DESTINATION', [false, 'The destination path']),
        OptString.new('SOURCE', [true, 'The directory or file to compress'])
      ], self.class)
  end

  def get_program_file_path
    get_env('ProgramFiles')
  end

  def has_7zip?
    file?("#{get_program_file_path}\\7-Zip\\7z.exe")
  end

  def vbs(dest, src)
    vbs_file = File.read(File.join(Msf::Config.data_directory, "post", "zip", "zip.vbs"))
    vbs_file << "WindowsZip \"#{src}\",\"#{dest}\""
    vbs_file
  end

  def upload_exec_vbs_zip
    script = vbs(datastore['DESTINATION'], datastore['SOURCE'])
    tmp_path = "#{get_env('TEMP')}\\zip.vbs"
    print_status("VBS file uploaded to #{tmp_path}")
    write_file(tmp_path, script)
    cmd_exec("wscript.exe #{tmp_path}")
  end

  def do_7zip
    program_file_path = get_program_file_path
    output = cmd_exec("#{program_file_path}\\7-Zip\\7z.exe a -tzip \"#{datastore['DESTINATION']}\" \"#{datastore['SOURCE']}\"")
    vprint_line(output)
  end

  def do_zip
    output = cmd_exec("zip -D -d -q -r #{datastore['DESTINATION']} #{datastore['SOURCE']}")
    vprint_line(output)
  end

  def windows_zip
    if has_7zip?
      print_status("Compressing #{datastore['DESTINATION']} via 7zip")
      do_7zip
    else
      print_status("Compressing #{datastore['DESTINATION']} via VBS")
      upload_exec_vbs_zip
    end
  end

  def linux_zip
    print_status("Compressing #{datastore['DESTINATION']} via zip")
    do_zip
  end

  def run
    os = get_target_os
    case os
    when Msf::Module::Platform::Windows.realname.downcase
      windows_zip
    else
      linux_zip
    end
  end

end

