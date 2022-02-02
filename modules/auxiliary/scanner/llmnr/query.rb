##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::LLMNR

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'LLMNR Query',
        'Description'    => %q(
          This module sends LLMNR queries, which are really just normal UDP DNS
          queries done (usually) over multicast on a different port, 5355.
          Targets other than the default RHOSTS' 224.0.0.252 should not respond
          but may anyway.
        ),
        'Author'         =>
          [
            'Jon Hart <jon_hart[at]rapid7.com>'
          ],
        'License'        => MSF_LICENSE
      )
    )
  end

  def scanner_prescan(batch)
    print_status("Sending LLMNR #{query_type_name}/#{query_class_name} queries for #{query_name} to #{batch[0]}->#{batch[-1]} port #{rport} (#{batch.length} hosts)")
    @results = {}
  end

  def scanner_postscan(_batch)
    found = {}
    @results.each_pair do |peer, resps|
      resps.each do |resp|
        found[peer] ||= {}
        next if found[peer][resp]
        response_info = describe_response(resp)
        print_good("#{peer} responded with #{response_info}")
        report_service(host: peer, port: rport, proto: "udp", name: "llmnr", info: response_info)
        found[peer][resp] = true
      end
    end
  end
end
