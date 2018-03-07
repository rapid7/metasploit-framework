##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'Memcached UDP Version Scanner',
      'Description' => %q(
          This module can be used to discover Memcached servers which expose the
          unrestricted UDP port 11211. A basic "version" request is executed to obtain
          the version of memcached.
      ),
      'Author'      =>
        [
          'Jon Hart <jon_hart@rapid7.com>' # Metasploit scanner module
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'Jul 23, 2003',
      'References' =>
          [
            ['URL', 'https://github.com/memcached/memcached/blob/master/doc/protocol.txt']
          ]
    )

    register_options(
      [
        Opt::RPORT(11211)
      ]
    )
  end

  def build_probe
    # Memcached version probe, per https://github.com/memcached/memcached/blob/master/doc/protocol.txt
    @memcached_probe ||= [
      rand(2**16), # random request ID
      0, # sequence number
      1, # number of datagrams in this sequence
      0, # reserved; must be 0
      "version\r\n"
    ].pack("nnnna*")
  end

  def scanner_process(data, shost, sport)
    # Check the response data for a "VERSION" repsonse
    if /VERSION (?<version>[\d\.]+)\r\n/ =~ data
      print_good("#{shost}:#{sport}/udp memcached version #{version}")
      report_service(
        host: shost,
        proto: 'udp',
        port: rport,
        info: version,
        name: 'memcached'
      )
    end
  end
end
