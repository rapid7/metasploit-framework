##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Docker Server Version Scanner',
      'Description' => %q{
        This module attempts to identify the version of a Docker Server running on a
        host. If you wish to see all the information available, set VERBOSE to true.
      },
      'Author'      => [ 'Agora-Security' ],
      'License'     => MSF_LICENSE
    ))
    register_options(
      [
        Opt::RPORT(2375)
      ])
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri' => '/version',
      'method' => 'GET'})
    if res.nil? || res.code != 200
      print_error("[Docker Version] failed to identify version")
      return
    end

    result = res.get_json_document
    print_status("Identifying Docker Server Version on #{peer}")
    print_good("[Docker Server] Version: #{result['Version']}")
    print_status ("All info: #{result.to_s}") if datastore['VERBOSE']
    report_note(
        :host  => ip,
        :port  => rport,
        :proto => 'tcp',
        :ntype => 'docker_version',
        :data  => result['Version'],
        :info  => "Docker Server v.#{result['Version']}"
    )
    print_status("Saving host information.")
    report_host(
        :host           => ip,
        :arch           => result['Arch'],
        :detected_arch  => result['Arch'],
        :os_family      => result['Os'],
        :info           =>  "Docker Server v.#{result['Version']} Kernel Version: #{result['KernelVersion']}"
    )
  end
end
