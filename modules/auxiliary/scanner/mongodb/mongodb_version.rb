##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bson'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Mongodb
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

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
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS]
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
    pkt = mongodb_build_packet('admin.$cmd', cmd.to_bson.to_s)

    sock.put(pkt)
    resp = sock.get_once(-1, 5)

    doc = mongodb_parse_doc(resp)
    return nil unless doc && doc['version']

    version_str = doc['version']
    report_service(
      host: rhost,
      port: rport,
      name: 'mongodb',
      proto: 'tcp',
      info: "MongoDB #{version_str}"
    )
    version_str
  rescue StandardError => e
    vprint_error("#{peer} - Failed to parse version: #{e.message}")
    nil
  end
end
