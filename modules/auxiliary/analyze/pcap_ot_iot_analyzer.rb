##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PCAP Analyzer for OT/IOT Devices',
        'Description' => %q{
          This module analyzes .pcap files to extract network information and identify OT/IOT devices.
          It generates a CSV output file with the extracted data.
        },
        'Author' => ['Jordi Ubach'],
        'License' => MSF_LICENSE,
        'References' => [
          ['Email', 'jordiubach@protonmail.com']
        ]
      )
    )

    register_options(
      [
        OptString.new('FILE_PCAP', [true, 'Path to the .pcap file to analyze']),
        OptString.new('FILE_PORT', [true, 'Path to the .txt file with port/protocol information']),
        OptString.new('FILE_OUT', [true, 'Path to the output .csv file'])
      ]
    )
  end

  def run
    # Verify input parameters
    unless File.exist?(datastore['FILE_PCAP']) && File.extname(datastore['FILE_PCAP']) == '.pcap'
      print_error("Invalid or non-existent PCAP file: #{datastore['FILE_PCAP']}")
      return
    end

    unless File.exist?(datastore['FILE_PORT']) && File.extname(datastore['FILE_PORT']) == '.txt'
      print_error("Invalid or non-existent port file: #{datastore['FILE_PORT']}")
      return
    end

    if File.exist?(datastore['FILE_OUT'])
      print_error("Output file already exists: #{datastore['FILE_OUT']}")
      return
    end

    # Hash of 100 common OT/IOT ports and their descriptions
    ot_iot_ports = {
      '21' => 'FTP - File Transfer Protocol',
      '22' => 'SSH - Secure Shell',
      '23' => 'Telnet',
      '25' => 'SMTP - Simple Mail Transfer Protocol',
      '37' => 'Time Protocol',
      '42' => 'WINS Replication',
      '43' => 'WHOIS Protocol',
      '53' => 'DNS - Domain Name System',
      '67' => 'DHCP - Dynamic Host Configuration Protocol (Server)',
      '68' => 'DHCP - Dynamic Host Configuration Protocol (Client)',
      '69' => 'TFTP - Trivial File Transfer Protocol',
      '80' => 'HTTP - Hypertext Transfer Protocol',
      '88' => 'Kerberos Authentication System',
      '102' => 'Siemens S7 - Industrial Control System Protocol',
      '123' => 'NTP - Network Time Protocol',
      '135' => 'EPMAP / DCE endpoint resolution',
      '137' => 'NetBIOS Name Service',
      '138' => 'NetBIOS Datagram Service',
      '139' => 'NetBIOS Session Service',
      '161' => 'SNMP - Simple Network Management Protocol',
      '162' => 'SNMP Trap',
      '389' => 'LDAP - Lightweight Directory Access Protocol',
      '443' => 'HTTPS - HTTP Secure',
      '445' => 'Microsoft-DS Active Directory',
      '465' => 'SMTPS - SMTP over TLS/SSL',
      '500' => 'ISAKMP - Internet Security Association and Key Management Protocol',
      '502' => 'Modbus - Industrial Control System Protocol',
      '514' => 'Syslog',
      '515' => 'LPD - Line Printer Daemon',
      '520' => 'RIP - Routing Information Protocol',
      '554' => 'RTSP - Real Time Streaming Protocol',
      '623' => 'IPMI - Intelligent Platform Management Interface',
      '636' => 'LDAPS - LDAP over TLS/SSL',
      '993' => 'IMAPS - IMAP over TLS/SSL',
      '995' => 'POP3S - POP3 over TLS/SSL',
      '1089' => 'FF Annunciation',
      '1090' => 'FF Fieldbus Message Specification',
      '1091' => 'FF System Management',
      '1433' => 'MSSQL Server',
      '1434' => 'MSSQL Monitor',
      '1521' => 'Oracle Database',
      '1604' => 'Citrix ICA - Independent Computing Architecture',
      '1720' => 'H.323',
      '1883' => 'MQTT - Message Queuing Telemetry Transport',
      '1911' => 'Niagara Fox',
      '1962' => 'PCWorx - Industrial Control System Protocol',
      '2000' => 'Cisco SCCP - Skinny Client Control Protocol',
      '2055' => 'NetFlow',
      '2123' => 'GTP-C - GPRS Tunneling Protocol Control',
      '2152' => 'GTP-U - GPRS Tunneling Protocol User',
      '2222' => 'EtherCAT - Industrial Ethernet Protocol',
      '2404' => 'IEC 60870-5-104 - Power System Control and Monitoring',
      '2455' => 'WAGO Industrial Control System',
      '2540' => 'LonWorks - Building Automation Protocol',
      '2541' => 'LonWorks2 - Building Automation Protocol',
      '3000' => 'HPOM - HP Operations Manager',
      '3306' => 'MySQL Database',
      '3389' => 'RDP - Remote Desktop Protocol',
      '4000' => 'Telematics',
      '4840' => 'OPC UA - Open Platform Communications Unified Architecture',
      '4911' => 'Niagara Fox',
      '5006' => 'Siemens S7 - Industrial Control System Protocol',
      '5007' => 'Siemens S7 - Industrial Control System Protocol',
      '5060' => 'SIP - Session Initiation Protocol',
      '5061' => 'SIP-TLS - SIP over TLS',
      '5094' => 'HART-IP - Highway Addressable Remote Transducer IP',
      '5353' => 'mDNS - Multicast DNS',
      '5671' => 'AMQP - Advanced Message Queuing Protocol (over TLS)',
      '5672' => 'AMQP - Advanced Message Queuing Protocol',
      '5683' => 'CoAP - Constrained Application Protocol',
      '5684' => 'CoAP-DTLS - CoAP over DTLS',
      '5800' => 'VNC - Virtual Network Computing',
      '6379' => 'Redis Database',
      '7400' => 'CODESYS - Industrial Control System Protocol',
      '7401' => 'CODESYS - Industrial Control System Protocol',
      '7402' => 'CODESYS - Industrial Control System Protocol',
      '7626' => 'SIMATICS7 - Siemens Industrial Control System',
      '8000' => 'QNX QCONN',
      '8080' => 'HTTP Alternate',
      '8443' => 'HTTPS Alternate',
      '8888' => 'HuaweiSymantec',
      '9100' => 'PDL Data Stream - Printer Job Language',
      '9200' => 'Elasticsearch',
      '9600' => 'OMRON FINS - Industrial Control System Protocol',
      '11112' => 'DICOM - Digital Imaging and Communications in Medicine',
      '18245' => 'GE SRTP - GE Intelligent Platforms SRTP',
      '18246' => 'GE SRTP - GE Intelligent Platforms SRTP',
      '20000' => 'DNP3 - Distributed Network Protocol',
      '27017' => 'MongoDB Database',
      '34962' => 'PROFInet RT Unicast',
      '34963' => 'PROFInet RT Multicast',
      '34964' => 'PROFInet Context Manager',
      '34980' => 'EtherCAT - Industrial Ethernet Protocol',
      '41100' => 'Siemens SICAM',
      '44818' => 'EtherNet/IP - Industrial Ethernet Protocol',
      '47808' => 'BACnet - Building Automation and Control Networks',
      '48898' => 'ADS - Automation Device Specification',
      '50000' => 'Siemens S7 Scalance',
      '55000' => 'FL-net - Industrial Control System Protocol',
      '56001' => 'Guardian AST',
      '62900' => 'ABB Ranger 2003',
      '1024' => 'Wago 750',
      '1102' => 'Wago 750',
      '5050' => 'Carel Industrial Control System',
      '4910' => 'Niagara Fox Industrial Control System',
      '4843' => 'OPC UA - Open Platform Communications Unified Architecture',
      '9999' => 'Telnet Alternative'
    }

    # Read custom ports from FILE_PORT
    custom_ports = {}
    File.readlines(datastore['FILE_PORT']).each do |line|
      port, protocol = line.strip.split('/')
      custom_ports[port] = protocol if port && protocol
    end

    # Initialize PCAP reader
    begin
      pcap = PacketFu::PcapFile.read_packets(datastore['FILE_PCAP'])
    rescue StandardError => e
      print_error("Error reading PCAP file: #{e.message}")
      print_error("File details:")
      print_error("  Path: #{datastore['FILE_PCAP']}")
      print_error("  Size: #{File.size(datastore['FILE_PCAP'])} bytes")
      print_error("  Magic bytes: #{File.open(datastore['FILE_PCAP'], 'rb') { |f| f.read(4).unpack('H*')[0] }}")
      return
    end

    # Open output CSV file
    CSV.open(datastore['FILE_OUT'], 'w') do |csv|
      csv << ['Date/Time', 'Source IP', 'Destination IP', 'Port', 'Protocol', 'MAC Address', 'Packet Size', 'OT/IOT Description']

      pcap.each do |packet|
        begin
          pkt = PacketFu::Packet.parse(packet)
          next unless pkt.is_ip?

          timestamp = Time.at(packet.timestamp.to_f).strftime('%y/%m/%d - %H:%M:%S')
          src_ip = pkt.ip_saddr
          dst_ip = pkt.ip_daddr
          protocol = pkt.proto.last
          mac_address = pkt.eth_saddr
          packet_size = pkt.size

          if pkt.is_tcp?
            port = pkt.tcp_dst.to_s
          elsif pkt.is_udp?
            port = pkt.udp_dst.to_s
          else
            next
          end

          ot_iot_desc = ot_iot_ports[port] || custom_ports[port] || ''

          csv << [timestamp, src_ip, dst_ip, port, protocol, mac_address, packet_size, ot_iot_desc]
        rescue StandardError => e
          print_error("Error processing packet: #{e.message}")
          next
        end
      end
    end

    print_good("Analysis complete. Results saved to #{datastore['FILE_OUT']}")
  end
end
