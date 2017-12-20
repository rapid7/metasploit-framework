##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::MQTT
  include Msf::Auxiliary::Report

  HANDLED_EXCEPTIONS = [
    Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused,
    ::Errno::ETIMEDOUT, ::Timeout::Error, ::EOFError
  ]

  def initialize
    super(
      'Name'        => 'Connect to and discover MQTT endpoints',
      'Description' => %q(
        This module attempts to establish a connection with MQTT endpoints.
      ),
      'Author'      => [
        'Jon Hart <jon_hart[at]rapid7.com>' # original metasploit module
      ],
      'References'  =>
        [
          ['URL', 'http://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html#_Table_3.1_-']
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run_host(ip)
    begin
      connect
      client = mqtt_client
      if mqtt_connect?(client)
        print_good("Connected to MQTT")
        # TODO: eventually we should subscribe to $SYS/# in order to get useful metadata:
        # $  mosquitto_sub -t '$SYS/#' -v
        # $SYS/broker/version mosquitto version 1.4.14
        # $SYS/broker/timestamp Mon, 10 Jul 2017 23:48:43 +0100
        report_service(
          host: ip,
          port: rport,
          proto: 'tcp',
          name: 'MQTT'
        )
      else
        vprint_error("Failed to connect to MQTT")
      end
    rescue *HANDLED_EXCEPTIONS => e
      vprint_error("error while connecting and negotiating: #{e}")
      return
    ensure
      mqtt_disconnect(client)
      disconnect
    end
  end
end
