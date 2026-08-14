##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MongoDB Version Detector',
        'Description' => %q{
          This module connects to a MongoDB instance and retrieves the server version
          using the buildInfo command. No authentication is required for this command.

          Tested against MongoDB 3.6.23
        },
        'References' => [
          [ 'URL', 'https://docs.mongodb.com/manual/reference/command/buildInfo/' ]
        ],
        'Author' => [
          'h00die'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => CRASH_SAFE,
          'SideEffects' => IOC_IN_LOGS
        }
      )
    )

    register_options(
      [
        Opt::RPORT(27017)
      ]
    )
  end

  def run_host(_ip)
    print_status("Connecting to #{peer}...")
    begin
      connect

      version = get_version
      if version
        print_good("#{peer} - MongoDB version: #{version}")
      else
        print_warning("#{peer} - Unable to retrieve MongoDB version")
      end
    rescue StandardError => e
      print_error("#{peer} - Connection failed: #{e}")
    ensure
      disconnect
    end
  end

  def get_version
    cmd = BSON::Document.new({ 'buildInfo' => BSON::Int32.new(1) })
    pkt = build_cmd_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    return nil unless resp && resp.length > 36

    buffer = BSON::ByteBuffer.new(resp[36..])
    doc = BSON::Document.from_bson(buffer)

    if doc && doc['version']
      version_str = doc['version']
      report_service(
        host: rhost,
        port: rport,
        name: 'mongodb',
        proto: 'tcp',
        info: "MongoDB #{version_str}"
      )
      return version_str
    end
    nil
  rescue StandardError => e
    vprint_error("#{peer} - Failed to parse version: #{e.message}")
    nil
  end

  def parse_doc(response)
    return nil if response.nil? || response.length <= 36

    buffer = BSON::ByteBuffer.new(response[36..])
    BSON::Document.from_bson(buffer)
  rescue StandardError
    nil
  end

  def build_cmd_packet(coll_name, bson_payload)
    coll_str = "#{coll_name}\x00"
    req_id = Rex::Text.rand_text(4)
    msg_len = 16 + 4 + coll_str.length + 4 + 4 + bson_payload.length

    packet = [msg_len].pack('V')
    packet << req_id
    packet << "\x00\x00\x00\x00"            # responseTo: 0
    packet << "\xd4\x07\x00\x00"            # OP_QUERY
    packet << "\x00\x00\x00\x00"            # flags
    packet << coll_str
    packet << "\x00\x00\x00\x00"            # numberToSkip: 0
    packet << "\x01\x00\x00\x00"            # numberToReturn: 1
    packet << bson_payload
    packet
  end
end
