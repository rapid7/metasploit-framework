##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Nifi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache NiFi Version Scanner',
        'Description' => %q{
          This module identifies Apache NiFi websites and reports their version number.

          Tested against NiFi major releases 1.14.0 - 1.21.0, and 1.11.0-1.13.0
          Also works against NiFi <= 1.13.0, but the module needs to be adjusted:
          set SSL false
          set rport 8080
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die',
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run_host(ip)
    vprint_status("Checking #{ip}")
    version = get_version

    if version.nil?
      print_bad("Apache NiFi not detected on #{ip}")
      return
    end

    print_good("Apache NiFi #{version} found on #{ip}")
  end
end
