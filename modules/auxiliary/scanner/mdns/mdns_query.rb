##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::MDNS

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'mDNS Query',
        'Description'    => %q(
          This module sends mDNS queries, which are really just normal UDP DNS
          queries done (usually) over multicast on a different port, 5353.
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
    print_status("Sending mDNS #{query_type_name} #{query_class_name} queries for " \
                 "#{query_name} to #{batch[0]}->#{batch[-1]} port #{rport} (#{batch.length} hosts)")
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
        report_service(host: peer, port: rport, proto: "udp", name: "mdns", info: response_info)
        found[peer][resp] = true
      end
    end
  end
end
