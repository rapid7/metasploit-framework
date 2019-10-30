##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/steam'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Rex::Proto::Steam

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Gather Steam Server Information',
        'Description'    => %q(
          This module uses the A2S_INFO request to obtain information from a Steam server.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References'     =>
          [
            # TODO: add more from https://developer.valvesoftware.com/wiki/Server_queries,
            # perhaps in different modules
            ['URL', 'https://developer.valvesoftware.com/wiki/Server_queries#A2S_INFO']
          ],
        'License'        => MSF_LICENSE
      )
    )

    register_options(
    [
      Opt::RPORT(27015)
    ])
  end

  def build_probe
    @probe ||= a2s_info
  end

  def scanner_process(response, src_host, src_port)
    info = a2s_info_decode(response)
    return unless info
    @results[src_host] ||= []
    if datastore['VERBOSE']
      print_good("#{src_host}:#{src_port} found '#{info.inspect}'")
    else
      print_good("#{src_host}:#{src_port} found '#{info[:name]}'")
    end
    @results[src_host] << info
  end

  def scanner_postscan(_batch)
    @results.each_pair do |host, info|
      report_host(host: host)
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'Steam',
        info: info
      )
    end
  end
end
