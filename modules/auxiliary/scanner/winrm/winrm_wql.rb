##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report


  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'WinRM WQL Query Runner',
      'Description'    => %q{
        This module runs WQL queries against remote WinRM Services.
        Authentication is required. Currently only works with NTLM auth.
        Please note in order to use this module, the 'AllowUnencrypted'
        winrm option must be set.
      },
      'Author'         => [ 'thelightcosine' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('WQL', [ true, "The WQL query to run", "Select Name,Status from Win32_Service" ]),
        OptString.new('USERNAME', [ true, "The username to authenticate as"]),
        OptString.new('PASSWORD', [ true, "The password to authenticate with"]),
        OptString.new('NAMESPACE', [true, 'The WMI namespace to use for queries', '/root/cimv2/'])
      ], self.class)
  end


  def run_host(ip)
    resp = send_winrm_request(winrm_wql_msg(datastore['WQL']))
    if resp.nil?
      print_error "Got no reply from the server"
      return
    end
    if resp.code == 401
      print_error "Login Failure! Recheck the supplied credentials."
      return
    end

    unless resp.code == 200
      print_error "Got unexpected response from #{ip}: \n #{resp.to_s}"
      return
    end
    resp_tbl = parse_wql_response(resp)
    print_good resp_tbl.to_s
    path = store_loot("winrm.wql_results", "text/csv", ip, resp_tbl.to_csv, "winrm_wql_results.csv", "WinRM WQL Query Results")
    print_status "Results saved to #{path}"
  end

end

=begin
To set the AllowUncrypted option:
winrm set winrm/config/service @{AllowUnencrypted="true"}
=end
