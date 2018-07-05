##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'HID discoveryd Information Discovery',
      'Description' => %q{
        Discover information from the discoveryd service
        exposed by HID VertX and Edge door controllers.
      },
      'Author'      => 'Brendan Coles',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'https://www.hidglobal.com/drivers/15654'],
          ['URL', 'http://nosedookie.blogspot.com/2011/07/identifying-and-querying-hid-vertx.html'],
          ['URL', 'https://github.com/coldfusion39/VertXploit'],
        ]
    )
    register_options [
      Opt::RPORT(4070),
      OptAddressRange.new('RHOSTS', [true, 'The multicast address or CIDR range of targets to query', '255.255.255.255'])
    ]
  end

  def rport
    datastore['RPORT']
  end

  def scanner_prescan(batch)
    print_status "Sending HID discover probe to #{batch.length} hosts"
    @results = {}
  end

  def scan_host(ip)
    vprint_status "#{ip}:#{rport} - Sending HID discover probe"
    scanner_send 'discover;013;', ip, rport
  end

  def scanner_postscan(_batch)
    if @results.empty?
      print_status 'No HID discoveryd services found.'
      return
    end

    found = {}
    @results.each_pair do |ip, responses|
      responses.uniq.each do |res|
        found[ip] ||= {}
        next if found[ip][res]

        response_info = parse_discovered_response res

        if response_info.nil?
          print_error "#{ip} responded with malformed data"
          next
        end

        msg = []
        msg << "Name: #{response_info[:name]}"
        msg << "Model: #{response_info[:model]}"
        msg << "Version: #{response_info[:version]} (#{response_info[:version_date]})"
        msg << "MAC Address: #{response_info[:mac]}"
        msg << "IP Address: #{response_info[:ip]}"

        print_good "#{ip} responded with:\n#{msg.join("\n")}"

        report_service(
          host: ip,
          mac: response_info[:mac],
          port: rport,
          proto: 'udp',
          name: 'hid-discoveryd',
          info: response_info
        )

        found[ip][res] = true
      end
    end
  end

  def parse_discovered_response(res)
    info = {}

    return unless res.start_with? 'discovered'

    hid_res = res.split(';')
    return unless hid_res.size == 9
    return unless hid_res[0] == 'discovered'
    return unless hid_res[1].to_i == res.length

    {
      :mac          => hid_res[2],
      :name         => hid_res[3],
      :ip           => hid_res[4],
      # ?           => hid_res[5], # '1'
      :model        => hid_res[6],
      :version      => hid_res[7],
      :version_date => hid_res[8]
    }
  end
end
