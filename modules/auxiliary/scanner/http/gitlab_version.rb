##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Gitlab
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Gitlab Version Scanner',
      'Description' => %q{
          This module scans a Gitlab install for information about its version.
      },
      'Author' => [ 'Julien (jvoisin) Voisin' ],
      'License' => MSF_LICENSE
    )
  end

  def run_host(ip)
    version = gitlab_version
    if version
      print_good("Gitlab version range for #{ip}:#{datastore['RPORT']}: #{version}")
      report_note(
        host: ip,
        port: datastore['RPORT'],
        proto: ssl ? 'https' : 'http',
        ntype: 'gitlab.version',
        data: { version: version }
      )
    else
      print_error("Unable to find Gitlab version for #{ip}.")
    end
  end
end
