require 'packetfu'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Capture

  FILE_NAME = 'bacnet-discovery'.freeze
  DEFAULT_SERVER_TIMEOUT = 3
  DEFAULT_SEND_COUNT = 1

  BACNET_ASHARE_STANDARD = "\x01".freeze
  BACNETIP_CONSTANT = "\x81".freeze
  BACNET_LLC = "\x82\x82\x03".freeze
  BACNET_BVLC = "\x81\x0b\x00\x0c".freeze
  BACNET_BVLC_LEN = BACNET_BVLC.length

  BACNET_WHOIS_APDU_NPDU = "\x01\x20\xff\xff\x00\xff\x10\x08".freeze

  # Building Automation and Control Network APDU
  #     0001 .... = APDU Type: Unconfirmed-REQ (1)
  #     Unconfirmed Service Choice: i-Am (0)
  #     ObjectIdentifier: device
  BACNET_UNCOFIRMED_REQ_I_AM_OBJ_DEVICE_PREFIX = "\x10\x00\xc4\x02".freeze
  DEFAULT_BACNET_PORT = 47808
  DISCOVERY_MESSAGE_L3 = BACNET_BVLC + BACNET_WHOIS_APDU_NPDU
  DISCOVERY_MESSAGE_L2 = BACNET_LLC + BACNET_WHOIS_APDU_NPDU
  DISCOVERY_MESSAGE_L2_LEN = Array[DISCOVERY_MESSAGE_L2.length].pack('n')

  READ_MULTIPLE_DEVICES_PROP = "\x1e\x09\x08\x1f".freeze
  READ_MODEL_NAME_PROP = "\x19\x46".freeze
  READ_FIRMWARE_VERSION_PROP = "\x19\x2c".freeze
  READ_APP_SOFT_VERSION_PROP = "\x19\x0c".freeze
  READ_DESCRIPTION_PROP = "\x19\x1c".freeze

  GET_PROPERTY_MESSAGES_L3_SIMPLE = [
    "\x81\n\u0000\u0011\u0001\u0004\u0002\u0002\u0000\f\f\u0002{object_identifier}#{READ_MODEL_NAME_PROP}", # model-name
    "\x81\n\u0000\u0011\u0001\u0004\u0002\u0002\u0000\f\f\u0002{object_identifier}#{READ_FIRMWARE_VERSION_PROP}", # firmware-revision
    "\x81\n\u0000\u0011\u0001\u0004\u0002\u0002\u0000\f\f\u0002{object_identifier}#{READ_APP_SOFT_VERSION_PROP}", # application-software-version
    "\x81\n\u0000\u0011\u0001\u0004\u0002\u0002\u0000\f\f\u0002{object_identifier}#{READ_DESCRIPTION_PROP}"
  ].freeze # description

  GET_PROPERTY_MESSAGES_L3_NESTED = [
    "\u0001${dest_net_id}{dadr_len}{dadr}\xFF\u0002\u0002\u0002\f\f\u0002{object_identifier}#{READ_MODEL_NAME_PROP}",
    "\u0001${dest_net_id}{dadr_len}{dadr}\xFF\u0002\u0002\u0002\f\f\u0002{object_identifier}#{READ_FIRMWARE_VERSION_PROP}",
    "\u0001${dest_net_id}{dadr_len}{dadr}\xFF\u0002\u0002\u0002\f\f\u0002{object_identifier}#{READ_APP_SOFT_VERSION_PROP}",
    "\u0001${dest_net_id}{dadr_len}{dadr}\xFF\u0002\u0002\u0002\f\f\u0002{object_identifier}#{READ_DESCRIPTION_PROP}"
  ].freeze

  def initialize
    super(
      'Name' => 'BACnet Scanner',
      'Description' => '
        Discover BACnet devices by broadcasting Who-is message, then poll
        discovered devices for properties including model name,
        software version, firmware revision and description.
      ',
      'Author' => ['Paz @ SCADAfence'],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [UNRELIABLE_SESSION],
        'SideEffects' => [SCREEN_EFFECTS]
      }
    )

    register_options(
      [
        OptInt.new('TIMEOUT', Array[true, 'The socket connect timeout in seconds', DEFAULT_SERVER_TIMEOUT]),
        OptInt.new('COUNT', Array[true, 'The number of times to send each packet', DEFAULT_SEND_COUNT]),
        OptPort.new('PORT', Array[true, 'BACnet/IP UDP port to scan (usually between 47808-47817)', DEFAULT_BACNET_PORT]),
        OptString.new('INTERFACE', Array[true, 'The interface to scan from', 'eth1']),
        OptAddressLocal.new('LHOST', [true, 'The local IP of selected interface'], regex: /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)(\.(?!$)|$)){4}$/)
      ], self.class
    )
    deregister_options('RHOSTS', 'FILTER', 'PCAPFILE')
  end

  def hex_to_bin(str)
    str.scan(/../).map { |x| x.hex.chr }.join
  end

  def bin_to_hex(str)
    str.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
  end

  # Create UDP packet with the l2 and l3 details.
  def create_packet_base
    udp_pkt = PacketFu::UDPPacket.new
    udp_pkt.ip_daddr = '255.255.255.255'
    udp_pkt.eth_daddr = 'ff:ff:ff:ff:ff:ff'
    udp_pkt.udp_dport = datastore['PORT']
    udp_pkt.udp_sport = rand(0xffff - 1024) + 1024
    udp_pkt.ip_ttl = 64

    begin
      udp_pkt.ip_saddr = datastore['LHOST'] # Get user-input ip address
      udp_pkt.eth_saddr = get_mac(datastore['INTERFACE']) # Get interface's mac address
    rescue StandardError => e
      raise e
    end
    udp_pkt
  end

  # Check if device is nested and extract relevant data
  def parse_npdu(data)
    is_nested = false
    if data.start_with? BACNET_ASHARE_STANDARD
      begin
        control = data[1].unpack1('C*')
        src_specifier = control & (1 << 3) != 0  # check if 4th bit is set
        dst_specifier = control & (1 << 5) != 0  # check if 6th bit is set
        idx = 2
        if dst_specifier
          dst_len = data[idx + 2].ord
          idx += 3 + dst_len
        end
        if src_specifier
          src_net_id = data[idx..idx + 1]
          sadr_len = data[idx + 2]
          sadr = data[idx + 3..idx + 2 + sadr_len.unpack1('C*')]
          idx += 3 + sadr_len.unpack1('C*')
          is_nested = true
        end
        idx += 1 if dst_specifier # increase index if both specifiers exist
        # if no network address specified - set as broadcast network address
        src_net_id ||= '\x00'
      rescue StandardError => e
        raise e
      end
    end
    [is_nested, src_net_id, sadr_len, sadr]
  end

  # Extracting index to start handling the data from
  def extract_index(data)
    if data.start_with? BACNET_ASHARE_STANDARD
      begin
        control = data[1].unpack1('C*')
        src_specifier = control & (1 << 3) != 0  # check if 4th bit is set
        dst_specifier = control & (1 << 5) != 0  # check if 6th bit is set
        idx = 2
        if dst_specifier
          idx += 3 + dst_len
        end
        if src_specifier
          sadr_len = data[idx + 2]
          idx += 3 + sadr_len.unpack1('C*')
        end
        idx += 1 if dst_specifier # increase index if both specifiers exist
        idx
      end
    end
  end

  # Broadcasting Who-is and returns a capture with the responses.
  def broadcast_who_is(udp_pkt)
    capture = PacketFu::Capture.new(iface: datastore['INTERFACE'], start: true, filter: "udp and src port #{datastore['PORT']}")
    datastore['COUNT'].times { udp_pkt.to_w(datastore['INTERFACE']) }
    sleep(datastore['TIMEOUT'])
    capture.save
    capture
  end

  # Analyze I-am packets,and prepare read-property messages for each.
  def analyze_i_am_devices(capture)
    devices_data = {}
    instance_numbers = []
    capture.array.each do |packet|
      mac = "#{bin_to_hex(packet[6])}:#{bin_to_hex(packet[7])}:#{bin_to_hex(packet[8])}:#{bin_to_hex(packet[9])}:#{bin_to_hex(packet[10])}:#{bin_to_hex(packet[11])}"
      ip = Rex::Socket.addr_ntoa(packet[26..29])
      next unless packet[42] == BACNETIP_CONSTANT # If packet is not a bacnet/ip

      data = packet[46..]
      index = data.index(BACNET_UNCOFIRMED_REQ_I_AM_OBJ_DEVICE_PREFIX)
      next unless index # If packet has no I-am object

      raw_instance_number = bin_to_hex(data[(index + BACNET_UNCOFIRMED_REQ_I_AM_OBJ_DEVICE_PREFIX.length)..(index + BACNET_UNCOFIRMED_REQ_I_AM_OBJ_DEVICE_PREFIX.length + 2)]).to_i(16) & 0x3fffff
      instance_number = raw_instance_number.to_s(16).rjust(6, '0')
      next if instance_numbers.include? instance_number # Pass if we already analysed this instance number

      devices_data[[instance_number, mac, ip]] = data unless devices_data[[instance_number, mac, ip]]
    end
    devices_data
  end

  def create_messages_for_devices(devices_data)
    messages = {}
    devices_data.each do |key, data|
      instance_number = hex_to_bin(key[0])
      items = parse_npdu(data) # Get specifier data
      # Check if device is nested and create messages accordingly
      if items[0] == true
        messages[key] = create_nested_messages(instance_number, items)
      else
        messages[key] = create_simple_messages(instance_number)
      end
    end
    messages
  end

  # Create messages for nested device and return them in array.
  def create_nested_messages(instance_number, items)
    nested_messages = []
    GET_PROPERTY_MESSAGES_L3_NESTED.each do |msg_base|
      msg = msg_base
            .sub('{object_identifier}', instance_number)
            .sub('{dest_net_id}', items[1])
            .sub('{dadr_len}', items[2])
            .sub('{dadr}', items[3])
      length = Array(msg.length + BACNET_BVLC_LEN).pack('n*')
      msg = "\x81\n#{length}#{msg}"
      nested_messages.append(msg)
    end
    nested_messages
  end

  # Create messages for non-nested device and return them in array.
  def create_simple_messages(instance_number)
    simple_messages = []
    GET_PROPERTY_MESSAGES_L3_SIMPLE.each do |msg_base|
      msg = msg_base.sub('{object_identifier}', instance_number)
      simple_messages.append(msg)
    end
    simple_messages
  end

  # Loop on recorded packets and extract data from read-property messages
  def extract_data(capture)
    asset_data = {}
    capture.array.each do |packet|
      data = packet[46..]
      items = parse_npdu(data)
      index = extract_index(data)
      asset_data['sadr'] = bin_to_hex(items[3]) if items[0] == true
      type = data[index + 8..index + 9]
      attribute = ''
      case type
      when READ_MODEL_NAME_PROP
        attribute = 'model-name'
      when READ_DESCRIPTION_PROP
        attribute = 'description'
      when READ_APP_SOFT_VERSION_PROP
        attribute = 'application-software-version'
      when READ_FIRMWARE_VERSION_PROP
        attribute = 'firmware-revision'
      else
        raise "undefined attribute for property number #{bin_to_hex(type)}."
      end
      begin
        value = bin_to_hex(data[index + 9..])[/3e(.*?)3f/m, 1]
        value = hex_to_bin(value)
        value = (value[value.index(hex_to_bin('00')) + 1..]).force_encoding('UTF-8') # parsing the needed text
        asset_data[attribute] = value
      rescue StandardError => e
        raise e
      end
    end
    asset_data
  end

  # Gets properties from devices and returns a hash with the details of each device.
  def get_properties_from_devices(messages, udp_pkt)
    devices_by_ip = {}
    messages.each do |key, message_block|
      instance_number = key[0].to_i(16)
      mac = key[1]
      ip = key[2]

      capture = send_read_properties(message_block, udp_pkt, mac, ip, instance_number)
      begin
        device = extract_data(capture)
        raise StandardError if device.empty?

        device['instance-number'] = instance_number.to_s
        devices_by_ip[ip] = [] unless devices_by_ip[ip]
        devices_by_ip[ip].append(device)
      rescue StandardError
        print_bad("Couldn't collect data for asset number #{instance_number}.")
      end
    end
    devices_by_ip
  end

  # Sending read-property packets and returns a pcap with the responses.
  def send_read_properties(messages, udp_pkt, mac, ip, instance_number)
    udp_pkt.eth_daddr = mac
    udp_pkt.ip_daddr = ip

    capture = PacketFu::Capture.new(iface: datastore['INTERFACE'], start: true,
                                    filter: "ip src #{ip} and ip dst #{udp_pkt.ip_saddr}")
    print_status("Querying device number #{instance_number} in ip #{ip}")
    messages.each do |message|
      udp_pkt.payload = message
      udp_pkt.recalc
      datastore['COUNT'].times { udp_pkt.to_w(datastore['INTERFACE']) }
    end
    sleep(datastore['TIMEOUT'])
    capture.save
    capture
  end

  # Iterates over all the devices and prints the details to the user.
  def output_results(devices_by_ip)
    devices_by_ip.each_value do |ip_group|
      ip_group.each do |asset|
        sadr = ''
        if asset['sadr']
          sadr = "sadr: #{asset['sadr']}\n"
        end
        print_good(<<~OUTPUT)
          for asset number #{asset['instance-number']}:
          \tmodel name: #{asset['model-name']}
          \tfirmware revision: #{asset['firmware-revision']}
          \tapplication software version: #{asset['application-software-version']}
          \tdescription: #{asset['description']}
          \t#{sadr}
        OUTPUT
      end
    end
  end

  # Convert data values to xml format.
  def parse_data_to_xml(raw_data)
    data = ''
    raw_data.each do |ip, devices|
      chunk = <<~IP.chomp
        <ip>
          <value> #{ip} </value>
      IP
      devices.each do |device|
        sadr = ''
        if device['sadr']
          sadr = "
          <sadr> #{device['sadr']} </sadr>"
        end
        chunk = <<~XML.chomp
          #{chunk}
              <asset>
                <instance-number> #{device['instance-number']} </instance-number>
                <model-name> #{device['model-name']} </model-name>
                <application-software-version> #{device['application-software-version']} </application-software-version>
                <firmware-revision> #{device['firmware-revision']} </firmware-revision>
                <description> #{device['description']} </description>#{sadr}
              </asset>
        XML
      end
      chunk += <<~IP

        </ip>
      IP
      data += chunk
    end
    data
  end

  def run
    # Validate user input
    raise Msf::OptionValidateError, ['TIMEOUT'] if datastore['TIMEOUT'].negative?
    raise Msf::OptionValidateError, ['COUNT'] if datastore['COUNT'] < 1
    raise Msf::OptionValidateError, ['INTERFACE'] if datastore['INTERFACE'].empty?

    begin
      # Create Base packet
      udp_pkt = create_packet_base

      # Add Who-is payload
      udp_pkt.payload = DISCOVERY_MESSAGE_L3
      udp_pkt.recalc

      begin
        # Prevent ICMP retransmission
        socket = UDPSocket.new
        socket.bind(udp_pkt.ip_saddr, udp_pkt.udp_sport)
      rescue StandardError
        raise StandardError, "Could not open a socket. Is '#{datastore['LHOST']}' a correct local IP?"
      end

      # Broadcast who-is and create request-property messages for detected devices.
      print_status "Broadcasting Who-is via #{datastore['INTERFACE']}"
      capture = broadcast_who_is(udp_pkt)
      devices_data = analyze_i_am_devices(capture)
      messages = create_messages_for_devices(devices_data)

      # If there are messages to send
      if !messages.empty?
        print_status "found #{messages.length} devices"
        devices_by_ip = get_properties_from_devices(messages, udp_pkt)
        print_status 'Done collecting data'
        output_results(devices_by_ip)
      else
        print_status('No devices found. Exiting.')
        return
      end
    rescue StandardError => e
      print_bad(e.message)
      return
    end
    socket.close
    begin
      data = parse_data_to_xml(devices_by_ip)
      store_local('bacnet.devices.info'.dup, 'text/xml', data, FILE_NAME)
      print_good("Successfully saved data to local store named #{FILE_NAME}.xml")
      print_status('Done.')
    rescue StandardError => e
      print_bad(e.message)
    end
  end
end
