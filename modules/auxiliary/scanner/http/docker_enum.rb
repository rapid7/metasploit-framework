##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Docker Server Version Scanner',
      'Description' => 'This module attempts to identify the version of the Docker Server running on a host.',
      'Author'      => [ 'Agora-Security' ],
      'License'     => MSF_LICENSE
    )
    register_options(
      [
        Opt::RPORT(2375),
      ])
    register_autofilter_ports([ 2375 ])
    deregister_options('RHOST')
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri'    => normalize_uri(datastore['URI'], "/version"),
      'method' => 'GET'})
    if res.nil? || res.code != 200
      print_error("[Docker Version] failed to identify version")
      return
    end

    parse_body(res.body)
  end

  def parse_body(body)
    result = res.get_json_document
    print_status("Identifying Docker Server Version on #{ip}:#{rport}")
    print_good("[Docker Server] Version: #{result['Version']}")
    if datastore['VERBOSE']
        print_status ("All info: #{result.to_s}")
    end
  end
end
