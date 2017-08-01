##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Wordpress Scanner',
      'Description' => 'Detects Wordpress installations and their version number',
      'Author'      => [ 'Christian Mehlmauer' ],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(target_host)
    print_status("Trying #{target_host}")
    if wordpress_and_online?
      version = wordpress_version
      version_string = version ? version : '(no version detected)'
      print_good("#{target_host} running Wordpress #{version_string}")
      report_note(
          {
              :host   => target_host,
              :proto  => 'tcp',
              :sname => (ssl ? 'https' : 'http'),
              :port   => rport,
              :type   => "Wordpress #{version_string}",
              :data   => target_uri
          })
    end
  end
end
