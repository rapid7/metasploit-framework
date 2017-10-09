##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Joomla
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Huge thanks to @zeroSteiner for helping me. Also thanks to @kaospunk. Finally thanks to
  # Joomscan and various MSF modules for code examples.
  def initialize
    super(
      'Name'        => 'Joomla Version Scanner',
      'Description' => %q{
          This module scans a Joomla install for information about the underlying
        operating system and Joomla version.
      },
      'Author'      => [ 'newpid0' ],
      'License'     => MSF_LICENSE
    )
  end

  def get_server_header
    # This module used to determine the operating system by the server header. But this is
    # not an accurate way to do OS detection, so we have toned it down to just returning the
    # header, and let the user decide.
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path)
    })

    if res && res.headers['Server']
      return res.headers['Server']
    end

    nil
  end

  def run_host(ip)
    unless joomla_and_online?
      print_error("It doesn't look like Joomla is up and running at #{target_uri.to_s}")
      return
    end

    server = get_server_header
    version = joomla_version

    if server
      print_status("Server: #{server}")
    else
      print_error("Unable to determine server.")
    end

    if version
      print_good("Joomla version: #{version}")
      report_note(
        host: ip,
        port: datastore['RPORT'],
        proto: ssl ? 'https' : 'http',
        ntype: 'joomla.version',
        data: version
      )
    else
      print_error("Unable to find Joomla version.")
    end
  end
end
