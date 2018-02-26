##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/quake'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner
  include Rex::Proto::Quake

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Gather Quake Server Information',
        'Description'   => %q(
          This module uses the getstatus or getinfo request to obtain
          information from a Quakeserver.
        ),
        'Author'        => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References'    =>
          [
            ['URL', 'ftp://ftp.idsoftware.com/idstuff/quake3/docs/server.txt']
          ],
        'License'       => MSF_LICENSE,
        'Actions'       => [
          ['status', 'Description' => 'Use the getstatus command'],
          ['info', 'Description' => 'Use the getinfo command']
        ],
        'DefaultAction' => 'status'
      )
    )

    register_options(
    [
      Opt::RPORT(27960)
    ])
  end

  def build_probe
    @probe ||= case action.name
               when 'status'
                 getstatus
               when 'info'
                 getinfo
               end
  end

  def decode_stuff(response)
    case action.name
    when 'info'
      stuff = decode_info(response)
    when 'status'
      stuff = decode_status(response)
    else
      stuff = {}
    end

    if datastore['VERBOSE']
      # get everything
      stuff
    else
      # try to get the host name, game name and version
      stuff.select { |k, _| %w(hostname sv_hostname gamename com_gamename version).include?(k) }
    end
  end

  def scanner_process(response, src_host, src_port)
    stuff = decode_stuff(response)
    return unless stuff
    @results[src_host] ||= {}
    print_good("#{src_host}:#{src_port} found '#{stuff}'")
    @results[src_host].merge!(stuff)
  end

  def scanner_postscan(_batch)
    @results.each_pair do |host, stuff|
      report_host(host: host)
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'Quake',
        info: stuff.inspect
      )
    end
  end
end
