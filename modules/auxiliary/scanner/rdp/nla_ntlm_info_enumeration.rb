##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::RDP
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'NLA NTLM Info Enumeration',
      'Description' => 'Extract the Windows host information from an RDP NLA NTLM challenge.',
      'References' => [ ['URL', 'https://fadedlab.wordpress.com/2019/06/13/using-nmap-to-extract-windows-info-from-rdp/' ] ],
      'Author' => [ 'Sam Bogart' ],
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(3389),
      ]
    )
  end

  def get_ntlmssp
    # warning: if rdp_check_protocol starts handling NLA, this will need to be updated
    is_rdp, server_selected_proto = rdp_check_protocol(RDPConstants::PROTOCOL_SSL | RDPConstants::PROTOCOL_HYBRID | RDPConstants::PROTOCOL_HYBRID_EX)
    return false, nil unless is_rdp
    return true, nil unless [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto

    swap_sock_plain_to_ssl
    ntlm_negotiate_blob = '' # see: https://fadedlab.wordpress.com/2019/06/13/using-nmap-to-extract-windows-info-from-rdp/
    ntlm_negotiate_blob << "\x30\x37\xa0\x03\x02\x01\x60\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28"
    ntlm_negotiate_blob << "\x4e\x54\x4c\x4d\x53\x53\x50\x00"  #  Identifier - NTLMSSP
    ntlm_negotiate_blob << "\x01\x00\x00\x00"                  #  Type: NTLMSSP Negotiate - 01
    ntlm_negotiate_blob << "\xb7\x82\x08\xe2"                  #  Flags (NEGOTIATE_SIGN_ALWAYS | NEGOTIATE_NTLM | NEGOTIATE_SIGN | REQUEST_TARGET | NEGOTIATE_UNICODE)
    ntlm_negotiate_blob << "\x00\x00"                          #  DomainNameLen
    ntlm_negotiate_blob << "\x00\x00"                          #  DomainNameMaxLen
    ntlm_negotiate_blob << "\x00\x00\x00\x00"                  #  DomainNameBufferOffset
    ntlm_negotiate_blob << "\x00\x00"                          #  WorkstationLen
    ntlm_negotiate_blob << "\x00\x00"                          #  WorkstationMaxLen
    ntlm_negotiate_blob << "\x00\x00\x00\x00"                  #  WorkstationBufferOffset
    ntlm_negotiate_blob << "\x0a"                              #  ProductMajorVersion = 10
    ntlm_negotiate_blob << "\x00"                              #  ProductMinorVersion = 0
    ntlm_negotiate_blob << "\x63\x45"                          #  ProductBuild = 0x4563 = 17763
    ntlm_negotiate_blob << "\x00\x00\x00"                      #  Reserved
    ntlm_negotiate_blob << "\x0f"                              #  NTLMRevision = 5 = NTLMSSP_REVISION_W2K3
    resp = rdp_send_recv(ntlm_negotiate_blob)

    ntlmssp_start = resp.index('NTLMSSP')
    if ntlmssp_start
      ntlmssp = NTLM_MESSAGE.parse(resp[ntlmssp_start..-1])
    end
    return is_rdp, ntlmssp
  end

  def run_host(_ip)
    rdp_connect
    is_rdp, ntlmssp = get_ntlmssp
    rdp_disconnect
    unless is_rdp
      vprint_error('Could not connect to RDP service.')
      return Exploit::CheckCode::Unknown
    end
    if ntlmssp.nil?
      vprint_error('Target does not support NLA')
      return Exploit::CheckCode::Unknown
    end

    os_version_struct = ntlmssp[:padding].value[0..4]
    os_version = os_version_struct.unpack('\C\C\v').join('.')

    target = ntlmssp[:target_info].value
    # Retrieve Domain name subblock info
    nb_domain = parse_ntlm_info(target, "\x02\x00", 0)
    # Retrieve Server name subblock info
    nb_name = parse_ntlm_info(target, "\x01\x00", nb_domain[:new_offset])
    # Retrieve DNS domain name subblock info
    dns_domain = parse_ntlm_info(target, "\x04\x00", nb_name[:new_offset])
    # Retrieve DNS server name subblock info
    dns_server = parse_ntlm_info(target, "\x03\x00", dns_domain[:new_offset])

    message = "Enumerated info on #{peer} - "
    message << "(NetBIOS Name: #{nb_name[:message]}) "
    message << "(NetBIOS Domain: #{nb_domain[:message]}) "
    message << "(Domain FQDN: #{dns_domain[:message]}) "
    message << "(Host FQDN: #{dns_server[:message]}) "
    message << "(OS Version: #{os_version})"
    print_good(message)

    report_note(
      host: rhost,
      port: rport,
      proto: 'tcp',
      sname: 'rdp',
      ntype: 'nla.ntlm.enumeration.info',
      data: {
        SMBName: nb_name[:message],
        SMBDomain: nb_domain[:message],
        FQDNDomain: dns_domain[:message],
        FQDNName: dns_server[:message],
        OSVersion: os_version
      },
      update: :unique_data
    )
  end

  def parse_ntlm_info(message, pattern, offset)
    name_index = message.index(pattern, offset)
    offset = name_index.to_i
    size = message[offset + 2].unpack('C').first
    return {
      message: message[offset + 3, size].gsub(/\0/, ''),
      new_offset: offset + size
    }
  end

end
