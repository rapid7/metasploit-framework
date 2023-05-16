##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'WinRM WQL Query Runner',
      'Description' => %q{
        This module runs WQL queries against remote WinRM Services.
        Authentication is required. Currently only works with NTLM auth.
        Please note in order to use this module, the 'AllowUnencrypted'
        winrm option must be set.
      },
      'Author' => [ 'thelightcosine' ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('WQL', [ true, 'The WQL query to run', 'Select Name,Status from Win32_Service' ]),
        OptString.new('NAMESPACE', [true, 'The WMI namespace to use for queries', 'root/cimv2'])
      ]
    )
  end

  def run
    check_winrm_parameters
    super
  end

  def run_host(ip)
    connection = create_winrm_connection
    wql_result = connection.run_wql(datastore['WQL'], "#{wmi_namespace}/*")
    result = parse_wql_hash(wql_result)
    print_good result.to_s
    path = store_loot('winrm.wql_results', 'text/csv', ip, result.to_csv, 'winrm_wql_results.csv', 'WinRM WQL Query Results')
    print_good "Results saved to #{path}"
  end
end
